package main

import (
	"fmt"
	"math/rand"
	"time"
	"votegral/pkg/actors"
	"votegral/pkg/config"
	"votegral/pkg/context"
	"votegral/pkg/crypto"
	"votegral/pkg/hardware"
	"votegral/pkg/io"
	"votegral/pkg/ledger"
	"votegral/pkg/log"
	"votegral/pkg/metrics"
	"votegral/pkg/protocol"
	"votegral/pkg/result"
)

// Simulation orchestrates the entire election simulation process.
// It holds the configuration, hardware connections, actors,
// and shared state like the ledger.
type Simulation struct {
	config   *config.Config
	ea       *actors.ElectionAuthority
	official *actors.ElectionOfficial
	printer  *actors.EnvelopePrinter
	kiosk    *actors.RegistrationKiosk
	voters   []*actors.Voter
	ledger   *ledger.Ledger
	hw       hardware.Hardware
}

func main() {
	// 1. Load configuration from flags.
	cfg := config.NewConfig()

	// 2. Initialize the simulation environment.
	sim, err := NewSimulation(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize simulation: %v", err)
	}

	// 3. Run the simulation.
	var runMetrics map[string]*metrics.AggregatedMetrics
	var tally *protocol.TallyOutput
	totalTimeRecorder := metrics.NewRecorder(cfg.PrintMetrics)
	if err = totalTimeRecorder.Record("TotalTime", func() error {
		runMetrics, tally, err = sim.Run()
		return err
	}); err != nil {
		log.Fatalf("Failed to run simulation: %v", err)
	}

	log.Info("Total Time: %s, Setup Time: %s, Registration Time: %s, Voting Time: %s, Tally Time: %s",
		totalTimeRecorder.GetMetric("TotalTime").WallClock.String(),
		runMetrics["TotalSetup"].WallClocks[0],
		sumDurations(runMetrics["TotalRegistration"].WallClocks),
		sumDurations(runMetrics["TotalVoting"].WallClocks),
		sumDurations(runMetrics["TotalTally"].WallClocks))

	// 4. Write the results to CSV files.
	resultsWriter := result.NewWriter(cfg.ResultsPath, cfg.System, sim.hw.Name(), cfg.Voters)
	if err = resultsWriter.WriteAllResults(runMetrics); err != nil {
		log.Fatalf("Failed to write results: %v", err)
	}

	fmt.Printf("--- Results ---\n")
	fmt.Printf("Registration Phase (WallClock): %s\n", sumDurations(runMetrics["TotalRegistration"].WallClocks))
	fmt.Printf("Tally Phase (WallClock): %s\n", sumDurations(runMetrics["TotalTally"].WallClocks))
	fmt.Printf("Option A: %d\n", tally.Results[0])
	fmt.Printf("Option B: %d\n", tally.Results[1])
	fmt.Printf("Winner: %s\n", tally.Winner)
}

func sumDurations(durations []time.Duration) time.Duration {
	total := time.Duration(0)
	for _, duration := range durations {
		total += duration
	}
	return total
}

// NewSimulation creates and initializes all components required for a simulation.
func NewSimulation(cfg *config.Config) (*Simulation, error) {
	log.Debug("Initializing crypto parameters, actors and hardware")

	// Initialize Crypto Parameters
	crypto.InitCryptoParams(cfg.Seed)

	// Initialize Actors
	sim := &Simulation{config: cfg}
	var err error
	sim.ea, err = actors.NewElectionAuthority(cfg.Talliers)
	if err != nil {
		return nil, err
	}
	sim.official, err = actors.NewElectionOfficial()
	if err != nil {
		return nil, err
	}
	sim.printer, err = actors.NewEnvelopePrinter()
	if err != nil {
		return nil, err
	}
	sim.kiosk, err = actors.NewRegistrationKiosk(sim.official.SignSymmCredential())
	if err != nil {
		return nil, err
	}

	// Initialize shared state and voters
	sim.ledger = ledger.NewLedger()
	sim.voters = make([]*actors.Voter, cfg.Voters)
	for i := uint64(0); i < cfg.Voters; i++ {
		sim.voters[i] = actors.NewVoter(i)
	}

	// Initialize hardware based on configuration
	sim.hw, err = hardware.New(cfg)
	if err != nil {
		return nil, err
	}

	return sim, nil
}

// Run runs the simulation
func (s *Simulation) Run() (map[string]*metrics.AggregatedMetrics, *protocol.TallyOutput, error) {
	log.Info("Starting simulation with %d voters on '%s' hardware...", s.config.Voters, s.config.HardwareType)
	var err error

	// --- Setup Phase ---
	setupRecorder := metrics.NewRecorder(s.config.PrintMetrics)
	setupCtx := context.NewContext(s.config, setupRecorder)
	if err = setupCtx.Recorder.Record("TotalSetup", func() error {
		return s.printer.GenerateEnvelopes(setupCtx, s.hw, s.ledger, s.config)
	}); err != nil {
		return nil, nil, fmt.Errorf("failed during simulation setup: %w", err)
	}

	// --- Per-Voter Simulation ---
	aggregator := metrics.NewAggregator()
	var voterMaterials []*io.VotingMaterials

	log.Info("--- Starting Per-Voter Simulation ---")

	for i := uint64(0); i < s.config.Voters; i++ {
		voter := s.voters[i]
		log.Debug("-- Registering voter with Voter ID: %d...", voter.VoterID())
		flow := protocol.NewFlow(s.official, s.kiosk, s.ea, s.printer, s.ledger, s.hw)

		// --- Registration ---
		regRecorder := metrics.NewRecorder(s.config.PrintMetrics)
		regCtx := context.NewContext(s.config, regRecorder)
		if err = regCtx.Recorder.Record("TotalRegistration", func() error {
			// -- Check-In (includes kiosk authorization)
			log.Debug("Checking In w/ Kiosk Authorization...")
			checkInBarcode, err := flow.CheckIn(regCtx, voter)
			if err != nil {
				return fmt.Errorf("failed to check in: %w", err)
			}

			// -- Real Credential Creation
			log.Debug("Creating Real Credential...")
			realMaterials, err := flow.CreateRealCredential(regCtx, voter, checkInBarcode)
			if err != nil {
				return fmt.Errorf("failed to create real credential: %w", err)
			}
			log.Trace("Generated real credential material for voter %d: %v", voter.VoterID(), realMaterials)
			voter.SetRealMaterial(realMaterials)

			// -- Fake/Test Credential Creation
			log.Debug("Creating %d Fake/Test Credentials...", s.config.FakeCredentialCount)
			for j := uint64(0); j < s.config.FakeCredentialCount; j++ {
				testMaterials, err := flow.CreateTestCredential(regCtx, voter)
				if err != nil {
					return fmt.Errorf("failed to create test credential #%d: %w", j+1, err)
				}
				log.Trace("Generated test credential material for voter %d: %v", voter.VoterID(), testMaterials)
				voter.AddTestMaterials(testMaterials)
			}

			// -- Check-Out
			log.Debug("Checking Out...")
			// Choose a random material for checkout
			voterMaterials = append([]*io.VotingMaterials{voter.RealMaterial()}, voter.TestMaterials()...)
			randomMaterial := voterMaterials[rand.Intn(len(voterMaterials))]
			if err = flow.CheckOut(regCtx, voter, randomMaterial); err != nil {
				return fmt.Errorf("failed to check out credential: %w", err)
			}

			// -- Activation
			log.Debug("Activating %d Credential(s)...", len(voterMaterials))
			for _, material := range voterMaterials {
				log.Trace("Activating credential %v...", material)
				err = flow.Activate(regCtx, voter, material)
				if err != nil {
					return fmt.Errorf("failed to activate credential: %w", err)
				}
			}

			return nil
		}); err != nil {
			return nil, nil, fmt.Errorf("failed during simulation for voter %d: %w", voter.VoterID(), err)
		}

		// Simulates the posting of the credentials onto the ledger by the election authority.
		// In a real system, this should be done periodically and randomly (e.g., once a week)
		// to prevent any kind of side channel timing attacks. This is completed on a
		// schedule so not included in any sub-metric.
		log.Debug("Election Authority Posting %d Credential(s) on Ledger...", len(voterMaterials))
		for _, material := range voterMaterials {
			s.ledger.AppendCredentialRecord(&ledger.CredentialEntry{CredPk: material.Credential.PublicKey()})
		}

		// --- Voting Phase ---
		// We now simulate each voter casting a vote using each of their credentials (real and fake).
		// For simplicity, only 0 or 1 is supported; we encrypt 0 for all real votes and 1 for all
		// fake votes. Therefore, the result of the tally phase should be equal to 0.
		log.Debug("Casting a Vote Per Credential (%d credentials)...", len(voterMaterials))
		// Setup metrics recorder and the context
		voteRecorder := metrics.NewRecorder(s.config.PrintMetrics)
		voteCtx := context.NewContext(s.config, voteRecorder)
		if err = voteCtx.Recorder.Record("TotalVoting", func() error {
			for a, material := range voterMaterials {
				var vote *ledger.VotingEntry
				if a == 0 { // All Real Credentials vote for option A.
					vote, err = flow.CreateVote(voteCtx, material, 0)
				} else { // All fake credentials vote for option B.
					vote, err = flow.CreateVote(voteCtx, material, 1)
				}
				// Tallying result should be option A with no votes for option B.

				if err != nil {
					return err
				}
				s.ledger.AppendVoteRecord(vote)
			}
			return nil
		}); err != nil {
			return nil, nil, fmt.Errorf("failed during voting phase: %w", err)
		}

		// The registration recorder calculates final derived metrics (e.g., CPU time).
		regRecorder.Finalize("TotalRegistration", []string{
			"Official_CheckIn", "Kiosk_Authorization",
			"Real_Credential_Creation", "Test_Credential_Creation",
			"CheckOut", "Activation",
		})
		//setupRecorder.Finalize("TotalSetup", []string{})
		//voteRecorder.Finalize("TotalVoting", []string{})

		aggregator.Add(setupRecorder)
		aggregator.Add(regRecorder)
		aggregator.Add(voteRecorder)
	}

	// --- Tallying Phase ---
	log.Info("--- Starting Tallying Phase ---")
	log.Info("Tallying %d votes across %d voters...", len(s.ledger.GetVotingRecords()), len(s.ledger.GetRegistrationRecords()))
	var tally *protocol.TallyOutput

	tallyRecorder := metrics.NewRecorder(s.config.PrintMetrics)
	tallyCtx := context.NewContext(s.config, tallyRecorder)
	if err = tallyCtx.Recorder.Record("TotalTally", func() error {
		tallyInput := protocol.NewTallyInput(s.config, s.ea, s.ledger)
		if tally, err = protocol.RunTally(tallyCtx, tallyInput); err != nil {
			return fmt.Errorf("tallying process failed: %w", err)
		}
		return err
	}); err != nil {
		return nil, nil, fmt.Errorf("failed during tallying phase: %w", err)
	}
	aggregator.Add(tallyRecorder)

	return aggregator.GetAggregatedMetrics(), tally, nil
}
