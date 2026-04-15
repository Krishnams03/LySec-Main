import unittest

from lysec.watchdog import WatchdogDaemon


class WatchdogServiceTargetTests(unittest.TestCase):
    def test_candidate_services_only_configured_service_by_default(self):
        cfg = {
            "daemon": {
                "pid_file": "/tmp/lysecd.pid",
                "watchdog": {
                    "service_name": "lysec-prelogin.service",
                },
            },
            "alerts": {},
        }
        wd = WatchdogDaemon(cfg)
        self.assertEqual(wd._candidate_services(), ["lysec-prelogin.service"])

    def test_candidate_services_honors_explicit_fallbacks(self):
        cfg = {
            "daemon": {
                "pid_file": "/tmp/lysecd.pid",
                "watchdog": {
                    "service_name": "lysec-prelogin.service",
                    "service_fallbacks": ["lysec.service"],
                },
            },
            "alerts": {},
        }
        wd = WatchdogDaemon(cfg)
        self.assertEqual(
            wd._candidate_services(),
            ["lysec-prelogin.service", "lysec.service"],
        )


if __name__ == "__main__":
    unittest.main()
