# Axon Demo Script
# Record with: vhs < docs/DEMO_SCRIPT.tape

Output docs/axon-demo.gif

Set Shell "bash"
Set FontSize 22
Set Width 1200
Set Height 600
Set Padding 20
Set Theme "Dracula"

# Step 1: Show the messy input
Type "cat examples/complex.sarif | head -n 20"
Enter
Sleep 2s

# Step 2: Run Axon Ingest (Zero-Copy Stdin)
Type "# Now, Axon ingests this instantly via Zero-Copy Stdin"
Enter
Sleep 1s
Type "cat examples/complex.sarif | axon ingest - -o report.json"
Enter
Sleep 3s

# Step 3: Show the high-fidelity summary
Type "# Look at that ANSI-colored summary. Clean and actionable."
Enter
Sleep 2s

# Step 4: Show the AI Fix (Neural Link)
Type "# Axon doesn't just find issues. It suggests fixes via Gemini 3.1 Pro."
Enter
Sleep 1s
Type "axon remediate --id CVE-2024-1234"
Enter
Sleep 5s

# Step 5: The flexible prompt
Type "y"
Sleep 1s
Enter

# Finish
Sleep 5s
