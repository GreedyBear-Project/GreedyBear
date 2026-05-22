from django.test import SimpleTestCase

from greedybear.cronjobs.commands.lsh import LSHConnectedComponents, UnionFind


class UnionFindTestCase(SimpleTestCase):
    def test_find_representative_applies_path_compression(self):
        u = UnionFind(4)
        u.parents = [0, 0, 1, 2]

        representative = u.find_representative(3)

        self.assertEqual(representative, 0)
        self.assertEqual(u.parents[3], 0)
        self.assertEqual(u.parents[2], 0)

    def test_union_merges_two_sets(self):
        u = UnionFind(3)

        u.union(0, 1)

        self.assertEqual(u.find_representative(0), u.find_representative(1))
        self.assertNotEqual(u.find_representative(0), u.find_representative(2))

    def test_union_same_element(self):
        u = UnionFind(3)

        u.union(1, 1)

        self.assertEqual(u.find_representative(1), 1)
        self.assertEqual(u.find_representative(0), 0)
        self.assertEqual(u.find_representative(2), 2)

    def test_union_by_rank_increments_rank_on_equal_rank_merge(self):
        u = UnionFind(4)

        u.union(0, 1)
        left_root = u.find_representative(0)
        self.assertEqual(u.ranks[left_root], 1)

        u.union(2, 3)
        right_root = u.find_representative(2)
        self.assertEqual(u.ranks[right_root], 1)

        u.union(left_root, right_root)

        final_root = u.find_representative(0)
        self.assertEqual(final_root, u.find_representative(1))
        self.assertEqual(final_root, u.find_representative(2))
        self.assertEqual(final_root, u.find_representative(3))
        self.assertEqual(u.ranks[final_root], 2)

    def test_union_by_rank_attaches_lower_rank_under_higher_rank(self):
        u = UnionFind(3)

        u.union(0, 1)
        higher_rank_root = u.find_representative(0)
        self.assertEqual(u.ranks[higher_rank_root], 1)

        lower_rank_root = u.find_representative(2)
        self.assertEqual(u.ranks[lower_rank_root], 0)

        u.union(lower_rank_root, higher_rank_root)

        self.assertEqual(u.find_representative(2), higher_rank_root)
        self.assertEqual(u.find_representative(0), higher_rank_root)
        self.assertEqual(u.find_representative(1), higher_rank_root)
        self.assertEqual(u.ranks[higher_rank_root], 1)


class LSHConnectedComponentsTestCase(SimpleTestCase):
    def test_get_min_hashes_generates_matching_signatures(self):
        lsh = LSHConnectedComponents(num_perm=64)
        sequences = [
            ["ls", "-la", "/tmp"],
            ["ls", "-la", "/tmp"],
            ["python", "-m", "http.server"],
        ]

        min_hashes = lsh._get_min_hashes(sequences)

        self.assertEqual(len(min_hashes), len(sequences))
        self.assertEqual(min_hashes[0].jaccard(min_hashes[1]), 1.0)
        self.assertLess(min_hashes[0].jaccard(min_hashes[2]), 0.5)

    def test_get_labels_maps_components_to_compact_labels(self):
        sequences = [["a"], ["b"], ["c"], ["d"], ["e"]]
        u = UnionFind(len(sequences))
        u.union(0, 2)
        u.union(2, 4)
        u.union(1, 3)

        labels = LSHConnectedComponents()._get_labels(sequences, u)

        self.assertEqual(labels, [0, 1, 0, 1, 0])

    def test_get_components_returns_empty_for_empty_input(self):
        labels = LSHConnectedComponents().get_components([])
        self.assertEqual(labels, [])

    def test_get_components_single_element_input(self):
        sequences = [["a", "b", "c"]]
        labels = LSHConnectedComponents().get_components(sequences)
        self.assertEqual(labels, [0])

    def test_get_components_all_identical_sequences(self):
        sequences = [
            ["same", "sequence"],
            ["same", "sequence"],
            ["same", "sequence"],
        ]
        labels = LSHConnectedComponents().get_components(sequences)
        self.assertEqual(labels, [0, 0, 0])

    def test_get_components_groups_similar_sequences(self):
        sequences = [
            ["echo", "hello", "world"],
            ["echo", "hello", "world"],
            ["wget", "http://example.com"],
            ["wget", "http://example.com"],
        ]

        labels = LSHConnectedComponents(threshold=0.8, num_perm=256).get_components(sequences)

        self.assertEqual(len(labels), 4)
        self.assertEqual(labels[0], labels[1])
        self.assertEqual(labels[2], labels[3])
        self.assertNotEqual(labels[0], labels[2])
