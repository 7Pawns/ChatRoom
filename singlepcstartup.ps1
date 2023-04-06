# Use Get-Command to find the path to the Python executable
$pythonPath = (Get-Command py).Source

# Paths to both scripts
$server = "server.py"
$client = "client.py"


# Start 2 Clients and don't display console
for($i = 1 ; $i -le 2; $i++)
{
    Start-Process powershell -WindowStyle hidden -ArgumentList "-noexit","& `"$pythonPath`" `"$client`"" 
}

# Run server
& $pythonPath $server 