import importlib
import os
import unittest


class ConfigSecurityDefaultsTest(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.copy()
        for name in (
            "SECRET_KEY",
            "DB_SERVER",
            "DB_USERNAME",
            "DB_PASSWORD",
            "LLM_API_KEY",
            "TRACE_SQL_HOST",
            "TRACE_SQL_USER",
            "TRACE_SQL_PASS",
            "NEO4J_URI",
            "NEO4J_USER",
            "NEO4J_PASSWORD",
        ):
            os.environ.pop(name, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)

    def test_config_defaults_do_not_embed_sensitive_values(self):
        import config

        importlib.reload(config)

        self.assertEqual("", config.Config.LLM_API_KEY)
        self.assertEqual("", config.Config.DB_PASSWORD)
        self.assertEqual("localhost,1433", config.Config.DB_SERVER)
        self.assertNotIn("sk" + "-", config.Config.SQL_CONN_STR)
        self.assertNotIn("123" + "123", config.Config.SQL_CONN_STR)
        self.assertNotIn("10" + ".21.", config.Config.SQL_CONN_STR)


if __name__ == "__main__":
    unittest.main()
