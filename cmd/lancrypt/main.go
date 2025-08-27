package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/sumanthd032/lancrypt/internal/transfer" 
)

// This is the root command for our CLI tool.
// All other commands (like 'send' and 'recv') will be attached to this.
var rootCmd = &cobra.Command{
	Use:   "lancrypt",
	Short: "LanCrypt is a tool for secure, peer-to-peer file sharing on a local network.",
	Long: `LanCrypt enables ephemeral, end-to-end encrypted file sharing directly 
over a local network, with no databases, no cloud, and no persistence.`,
	// This function will run if no sub-command is provided.
	Run: func(cmd *cobra.Command, args []string) {
		// Print help information if the user just runs 'lancrypt'
		cmd.Help()
	},
}

// The send command will handle sending files.
var sendCmd = &cobra.Command{
	Use:   "send [file]",
	Short: "Send a file to a peer on the local network",
	Long:  `Encrypts and sends a file to a receiving peer. It will generate a transfer code for the receiver to use.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		fmt.Printf("Initializing to send file: %s\n", filePath)

		// Create a new Sender.
		sender, err := transfer.NewSender(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating sender: %v\n", err)
			os.Exit(1)
		}
		// Ensure the listener is closed when we're done.
		defer sender.Close()

		// Start the sender process. This will block until a receiver connects.
		if err := sender.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error during transfer: %v\n", err)
			os.Exit(1)
		}
	},
}

// The recv command will handle receiving files.
var recvCmd = &cobra.Command{
	Use:   "recv",
	Short: "Receive a file from a peer on the local network",
	Long:  `Receives a file from a sending peer using a transfer code.`,
	Run: func(cmd *cobra.Command, args []string) {
		code, _ := cmd.Flags().GetString("code")
		if code == "" {
			fmt.Println("Error: a transfer --code is required.")
			os.Exit(1)
		}
		fmt.Printf("Initializing to receive file with code: %s\n", code)
		// TODO: Implement receiver logic in Step 2
	},
}

// This function runs at the very beginning.
// It sets up our commands and flags.
func init() {
	// Add a required '--code' flag to the 'recv' command.
	recvCmd.Flags().StringP("code", "c", "", "The transfer code from the sender")
	recvCmd.MarkFlagRequired("code")

	// Add the 'send' and 'recv' commands to our root command.
	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(recvCmd)
}

// The main function is the entry point of our application.
func main() {
	// Execute the root command. Cobra will figure out which command
	// needs to run based on the user's input.
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your command: '%s'", err)
		os.Exit(1)
	}
}
