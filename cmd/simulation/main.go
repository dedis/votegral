package main

import (
	"fmt"
	"math/rand"
	"os"
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
	metrics  *metrics.Recorder
	ea       *actors.ElectionAuthority
	official *actors.ElectionOfficial
	printer  *actors.EnvelopePrinter
	kiosk    *actors.Kiosk
	voters   []*actors.Voter
	ledger   *ledger.Ledger
	hw       hardware.Hardware
}

func main() {
	// 1. Load configuration from flags.
	cfg := config.NewConfig()

	analyzer := metrics.NewAnalyzer()

	for run := uint64(0); run < cfg.Runs; run++ {
		log.Info("----- Starting run %d of %d -----", run+1, cfg.Runs)

		rec := metrics.NewRecorder()

		// Initialize the simulation environment.
		sim, err := NewSimulation(cfg, rec)
		if err != nil {
			log.Fatalf("Failed to initialize simulation: %v", err)
		}

		// Run the simulation
		if err = sim.metrics.Record("Simulation", metrics.MLogic, func() error {
			return sim.Run()
		}); err != nil {
			log.Fatalf("Failed to run simulation: %v", err)
		}

		if cfg.PrintMetrics {
			rec.PrintTree(os.Stdout, cfg.MaxDepth, cfg.MaxChildren)
		}

		// Add measurements to the analyzer
		analyzer.Add(rec)
	}

	// Get the raw aggregated metrics from all runs.
	finalAnalysis := analyzer.Analyze()

	// Write the results to CSV files.
	resultsWriter := result.NewWriter(cfg.ResultsPath, cfg.System, string(cfg.HardwareType), cfg.Runs, cfg.Voters)
	if err := resultsWriter.WriteAllResults(finalAnalysis); err != nil {
		log.Fatalf("Failed to write results: %w", err)
	}

	printConsoleSummary(finalAnalysis)
}

func printConsoleSummary(result metrics.AnalysisResult) {
	fmt.Println("\n-------------------------------------------------")
	fmt.Printf("--- Median Phase Times (Per Simulation Run) ---\n")
	fmt.Println("-------------------------------------------------")

	phases := []string{"Simulation", "Setup", "Registration", "Voting", "Tally"}
	for a, phase := range phases {
		if comp, ok := result.Components[phase]; ok {
			if summary, ok := comp.Summaries["WallClock"]; ok {
				fmt.Printf("Median %-18s Time: %s\n", phase, summary.WallClock.P50)
				if a == 0 {
					fmt.Println("-------------------------------------------------")
				}
			}
		}
	}
	fmt.Println("-------------------------------------------------")
}

// NewSimulation creates and initializes all components required for a simulation.
func NewSimulation(cfg *config.Config, rec *metrics.Recorder) (*Simulation, error) {
	log.Debug("Initializing crypto parameters, actors and hardware")

	// Initialize Crypto Parameters
	crypto.InitCryptoParams(cfg.Seed)

	// Initialize Actors
	sim := &Simulation{config: cfg, metrics: rec}
	var err error
	sim.ea, err = actors.NewElectionAuthority(cfg.EAMembers)
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
func (s *Simulation) Run() error {
	log.Info("Starting simulation with %d voters on '%s' hardware...", s.config.Voters, s.config.HardwareType)
	var err error

	// Run Context
	runCtx := context.NewContext(s.config, s.metrics)
	flow := protocol.NewFlow(s.official, s.kiosk, s.ea, s.printer, s.ledger, s.hw)

	// --- Setup Phase ---
	if err = s.metrics.Record("Setup", metrics.MLogic, func() error {
		return s.printer.GenerateEnvelopes(runCtx, s.hw, s.ledger, s.config)
	}); err != nil {
		return fmt.Errorf("failed during run setup: %w", err)
	}

	log.Info("--- Starting Per-Voter Simulation (Registration and Voting) ---")
	if err = s.metrics.Record("Registration", metrics.MLogic, func() error {
		for _, voter := range s.voters {
			log.Debug("-- Registering voter with Voter ID: %d...", voter.VoterID())

			var voterCreds []*io.VotingMaterials

			if err = s.metrics.Record("RegisterAVoter", metrics.MLogic, func() error {
				log.Debug("CheckIn w/ Kiosk Authorization...")
				err = flow.CheckIn(runCtx, voter)
				if err != nil {
					return fmt.Errorf("failed to check in: %w", err)
				}

				log.Debug("Creating Real Credential...")
				if err = s.metrics.Record("CreateARealCredential", metrics.MLogic, func() error {
					return flow.CreateRealCredential(runCtx, voter)
				}); err != nil {
					return fmt.Errorf("failed to create real credential: %w", err)
				}

				log.Debug("Creating %d Fake/Test Credentials...", s.config.FakeCredentialCount)
				for j := uint64(0); j < s.config.FakeCredentialCount; j++ {
					if err = s.metrics.Record("CreateAFakeCredential", metrics.MLogic, func() error {
						return flow.CreateTestCredential(runCtx, voter)
					}); err != nil {
						return fmt.Errorf("failed to create test credential #%d: %w", j+1, err)
					}
				}

				// Fetch all voter Credentials
				voterCreds = append([]*io.VotingMaterials{voter.RealMaterial()}, voter.TestMaterials()...)

				// -- Check-Out
				log.Debug("Checking Out...")
				if err = s.metrics.Record("CheckoutAVoter", metrics.MLogic, func() error {
					randomMaterial := voterCreds[rand.Intn(len(voterCreds))] // Choose a random material for checkout
					return flow.CheckOut(runCtx, voter, randomMaterial)
				}); err != nil {
					return fmt.Errorf("failed to check out: %w", err)
				}

				// -- Activation
				log.Debug("Activating %d Credential(s)...", len(voterCreds))
				for _, material := range voterCreds {
					if err = s.metrics.Record("ActivateACredential", metrics.MLogic, func() error {
						return flow.Activate(runCtx, voter, material)
					}); err != nil {
						return fmt.Errorf("failed to activate credential: %w", err)
					}
				}

				// Simulates the posting of the credentials onto the ledger by the election authority.
				// In a real system, this should be done periodically and randomly (e.g., once a week)
				// to prevent any kind of side channel timing attacks.
				log.Debug("Election Authority Posting %d Credential(s) on Ledger...", len(voterCreds))
				_ = s.metrics.Record("EAPostingCreds", metrics.MLogic, func() error {
					for _, material := range voterCreds {
						s.ledger.AppendCredentialRecord(&ledger.CredentialEntry{CredPk: material.Credential.PublicKey()})
					}
					return nil
				})

				return nil
			}); err != nil {
				return fmt.Errorf("failed during registration for voter %d: %w", voter.VoterID(), err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed during registration phase: %w", err)
	}

	// --- Voting Phase ---
	// We now simulate each voter casting a vote using each of their credentials (real and fake).
	// We have all real credentials to vote for candidate A.
	if err = s.metrics.Record("Voting", metrics.MLogic, func() error {
		for _, voter := range s.voters {
			voterCreds := append([]*io.VotingMaterials{voter.RealMaterial()}, voter.TestMaterials()...)
			log.Debug("Casting a Vote Per Credential (%d credentials)...", len(voterCreds))
			for j, material := range voterCreds {
				if err = s.metrics.Record("CastAVote", metrics.MLogic, func() error {
					if j == 0 { // All Real Credentials vote for option A.
						return flow.CastVote(runCtx, material, 0)
					} else { // All fake credentials vote for option B.
						return flow.CastVote(runCtx, material, 1)
					}
				}); err != nil {
					return fmt.Errorf("failed during voting phase: %w", err)
				}
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed during voting phase: %w", err)
	}

	// --- Tallying Phase ---
	log.Info("--- Starting Tallying Phase ---")
	log.Info("Tallying %d votes across %d voters...", len(s.ledger.GetVotingRecords()), len(s.ledger.GetRegistrationRecords()))

	if err = s.metrics.Record("Tally", metrics.MLogic, func() error {
		tallyInput := protocol.NewTallyInput(s.config, s.ea, s.ledger)
		return protocol.RunTally(runCtx, tallyInput)
	}); err != nil {
		return fmt.Errorf("failed during tallying phase: %w", err)
	}

	return nil
}
