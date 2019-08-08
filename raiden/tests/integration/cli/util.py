def expect_cli_until_acknowledgment(child):
    #child.expect("Welcome to RIF Lumino Payments Protocol, Version 0.1")
    #child.expect("Have you read and understood and do you accept the RIF Lumino Disclosure Agreement and Privacy Warning?")
    child.sendline("y")


def expect_cli_until_account_selection(child):
    expect_cli_until_acknowledgment(child)
    child.expect("The following accounts were found in your machine:")
    child.expect("Select one of them by index to continue: ")
    child.sendline("0")


def expect_cli_successful_connected(child, mode):
    child.expect(f"Raiden is running in {mode} mode")
    child.expect("You are connected")
    child.expect("The Lumino API RPC server is now running")


def expect_cli_normal_startup(child, mode):
    expect_cli_until_acknowledgment(child)
    expect_cli_successful_connected(child, mode)
