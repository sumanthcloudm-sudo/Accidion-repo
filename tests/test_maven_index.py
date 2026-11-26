import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starter_kit import build_maven_index, enrich_maven_finding


def node(artifact, children=()):
    return dict(groupId="example", artifactId=artifact, version="1", children=list(children))


class MavenIndexTests(unittest.TestCase):
    def test_paths_and_cached_declarations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = node("app", [node("parent", [node("leaf")])])
            (root / "maven-dependency-tree-0.json").write_text(json.dumps(tree))
            index = build_maven_index(root)
            cache = {}
            with patch("starter_kit.find_maven_declaration", return_value=("pom.xml", 3, 8)) as lookup:
                with patch("pathlib.Path.read_text", side_effect=AssertionError("Unexpected reread")):
                    for _ in range(2000):
                        issue = dict(maven_coordinate="example:leaf", installed_version="1")
                        enrich_maven_finding(issue, root, root, index, cache)
                        self.assertEqual(issue["dependency_type"], "Transitive")
                        self.assertEqual(issue["dependency_chains"], ["example:app:1 -> example:parent:1 -> example:leaf:1"])
                        self.assertEqual(issue["direct_dependency"], "example:parent")
                        self.assertEqual(issue["direct_dependency_start_line"], 3)
                lookup.assert_called_once()

    def test_multiple_paths_and_missing_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = node("app", [node("leaf"), node("parent", [node("leaf")])])
            for number in range(2):
                (root / f"maven-dependency-tree-{number}.json").write_text(json.dumps(tree))
            index = build_maven_index(root)
            issue = dict(maven_coordinate="example:leaf", installed_version="1")
            enrich_maven_finding(issue, root, root, index, {})
            self.assertEqual(issue["dependency_type"], "Direct and Transitive")
            self.assertEqual(len(issue["dependency_chains"]), 2)
            missing = dict(maven_coordinate="example:leaf", installed_version="2")
            enrich_maven_finding(missing, root, root, index, {})
            self.assertNotIn("dependency_chains", missing)


if __name__ == "__main__":
    unittest.main()
