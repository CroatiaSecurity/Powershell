function Respond-ToThreat {
    param($Verdict, $Context)

    switch ($Verdict) {

        "Critical" {
            Suspend-Process -Id $Context.PID -ErrorAction SilentlyContinue
            Block-ProcessNetwork $Context.Path
            Collect-Evidence $Context
        }

        "High" {
            Block-ProcessNetwork $Context.Path
            Alert "High threat detected" $Context
        }

        "Medium" {
            Alert "Suspicious activity" $Context
        }
    }
}
