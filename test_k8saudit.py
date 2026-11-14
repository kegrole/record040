# Compatibility entry point so the required command works from the repo root:
#     python -m unittest test_k8saudit -v
from tests.test_k8saudit import *  # noqa: F401,F403

if __name__ == "__main__":
    import unittest

    unittest.main()
