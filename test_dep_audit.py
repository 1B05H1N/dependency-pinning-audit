import unittest

import dep_audit as da


def by_pkg(findings):
    return {f["package"]: f for f in findings}


class RequirementsTests(unittest.TestCase):
    def setUp(self):
        text = (
            "requests==2.31.0\n"
            "flask>=2.0\n"
            "django\n"
            "boto3==1.34.*\n"
            "-e git+https://example.com/pkg.git#egg=customlib\n"
            "pytest==8.2.0 ; python_version >= \"3.9\"\n"
            "# a comment\n"
        )
        self.findings = da.audit_requirements(text)
        self.map = by_pkg(self.findings)

    def test_pinned_not_flagged(self):
        self.assertNotIn("requests", self.map)
        self.assertNotIn("pytest", self.map)  # pinned even with env marker

    def test_range_medium(self):
        self.assertEqual(self.map["flask"]["severity"], "medium")

    def test_unpinned_high(self):
        self.assertEqual(self.map["django"]["severity"], "high")

    def test_wildcard_high(self):
        self.assertEqual(self.map["boto3"]["severity"], "high")

    def test_vcs_high(self):
        self.assertTrue(any(f["severity"] == "high" and "VCS" in f["message"] for f in self.findings))


class PackageJsonTests(unittest.TestCase):
    def setUp(self):
        obj = {
            "dependencies": {
                "express": "4.19.2",
                "lodash": "^4.17.21",
                "left-pad": "*",
                "react": "latest",
                "internal-lib": "git+https://example.com/x.git",
            },
            "devDependencies": {"eslint": ">=8.0.0"},
        }
        self.map = by_pkg(da.audit_package_json(obj))

    def test_exact_ok(self):
        self.assertNotIn("express", self.map)

    def test_caret_medium(self):
        self.assertEqual(self.map["lodash"]["severity"], "medium")

    def test_wildcard_and_latest_high(self):
        self.assertEqual(self.map["left-pad"]["severity"], "high")
        self.assertEqual(self.map["react"]["severity"], "high")

    def test_vcs_high(self):
        self.assertEqual(self.map["internal-lib"]["severity"], "high")

    def test_range_medium(self):
        self.assertEqual(self.map["eslint"]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
