package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/sumanthd032/lancrypt/internal/transfer"
)

var rootCmd = &cobra.Command{
	Use:   "lancrypt",
	Short: "LanCrypt is a tool for secure, peer-to-peer file sharing on a local network.",
	Long: `LanCrypt enables ephemeral, end-to-end encrypted file sharing directly 
over a local network, with no databases, no cloud, and no persistence.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var sendCmd = &cobra.Command{
	Use:   "send [file]",
	Short: "Send a file to a peer on the local network",
	Long:  `Encrypts and sends a file to a receiving peer. It will generate a transfer code for the receiver to use.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		passphrase, _ := cmd.Flags().GetString("passphrase")

		sender, err := transfer.NewSender(filePath, passphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating sender: %v\n", err)
			os.Exit(1)
		}
		defer sender.Close()

		if err := sender.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error during transfer: %v\n", err)
			os.Exit(1)
		}
	},
}

var recvCmd = &cobra.Command{
	Use:   "recv",
	Short: "Receive a file from a peer on the local network",
	Long:  `Receives a file from a sending peer using a transfer code, discovered automatically on the LAN.`,
	Run: func(cmd *cobra.Command, args []string) {
		code, _ := cmd.Flags().GetString("code")
		passphrase, _ := cmd.Flags().GetString("passphrase")

		receiver, err := transfer.NewReceiver(code, passphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating receiver: %v\n", err)
			os.Exit(1)
		}

		if err := receiver.Connect(); err != nil {
			fmt.Fprintf(os.Stderr, "Error during transfer: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	// Add passphrase flag to send command
	sendCmd.Flags().StringP("passphrase", "p", "", "Optional passphrase for extra security")

	// Add passphrase flag to recv command
	recvCmd.Flags().StringP("passphrase", "p", "", "Optional passphrase for extra security")
	recvCmd.Flags().StringP("code", "c", "", "The transfer code from the sender")
	recvCmd.MarkFlagRequired("code")

	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(recvCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your command: '%s'", err)
		os.Exit(1)
	}
}
