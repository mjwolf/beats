from auditbeat import BaseTest
from beat.beat import Proc
import time
import subprocess


class Test(BaseTest):
    def test_proc_exec(self):
        """
        execute a process, and ensure it's detected
        """
        process_name = "whoami"

        self.render_config_template(
            modules=[{
                "name": "auditd",
                "extras": {
                    "audit_rules": """ |
    -a always,exit -F arch=b64 -S execve,execveat -k exec
    -a always,exit -F arch=b64 -S exit_group
""",
                },
            }],
        )

        beat = self.start_beat()

        self.wait_log_contains("Successfully added 3 of 3 audit rules.",
                               max_timeout=30, ignore_case=True)

        # Need a bit more time to start after successful log message to be
        # really ready to capture processes
        time.sleep(3)

        subprocess.call([process_name])

        # TODO: validate entire log message contains correct proc details
        self.wait_log_contains(process_name, max_timeout=20, ignore_case=True)

        beat.check_kill_and_wait()
