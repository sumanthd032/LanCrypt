package transfer

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// promptForConfirmation displays the SAS and waits for the user to confirm.
func promptForConfirmation(sas string) error {
	fmt.Println("--------------------------------------------------")
	fmt.Println("Please verify the following authentication string")
	fmt.Println("with the other user:")
	fmt.Printf("\n    ✅ %s ✅\n\n", sas)
	fmt.Println("--------------------------------------------------")
	fmt.Print("Do these strings match? (y/n): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("could not read confirmation: %w", err)
	}

	input = strings.TrimSpace(strings.ToLower(input))

	if input != "y" && input != "yes" {
		return fmt.Errorf("user aborted transfer")
	}

	fmt.Println("Confirmation received.")
	return nil
}
