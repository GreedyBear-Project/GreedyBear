from datasketch import MinHash, MinHashLSH


class UnionFind:
    """
    A Union-Find data structure implementation.
    For details see here:
    https://www.geeksforgeeks.org/dsa/introduction-to-disjoint-set-data-structure-or-union-find-algorithm/

    This data structure supports two primary operations:
    - Find: Determine which subset a particular element is in
    - Union: Join two subsets into a single subset
    """

    def __init__(self, size: int):
        """
        Initialize Union-Find structure with given size.

        Args:
            size (int): Number of elements in the data structure
        """
        self.parents = list(range(size))
        self.ranks = [0] * size

    def find_representative(self, i: int) -> int:
        """
        Find the representative of the set containing element i.
        Uses path compression optimization to flatten the tree structure,
        making subsequent find operations faster.

        Args:
            i (int): Element to find the representative for

        Returns:
            int: The representative of the set containing i
        """
        if self.parents[i] != i:
            self.parents[i] = self.find_representative(self.parents[i])
        return self.parents[i]

    def union(self, i: int, j: int) -> None:
        """
        Union the sets containing elements i and j.
        After this operation, i and j will be in the same connected component.

        Args:
            i (int): an element
            j (int): another element
        """
        i_representative = self.find_representative(i)
        j_representative = self.find_representative(j)
        if i_representative == j_representative:
            return

        # Attach the shorter tree under the taller one to keep finds efficient (union by rank).
        if self.ranks[i_representative] < self.ranks[j_representative]:
            self.parents[i_representative] = j_representative
        elif self.ranks[i_representative] > self.ranks[j_representative]:
            self.parents[j_representative] = i_representative
        else:
            self.parents[j_representative] = i_representative
            self.ranks[i_representative] += 1


class LSHConnectedComponents:
    """
    Finds connected components in a collection of sequences using Locality-Sensitive Hashing.

    This class uses MinHash signatures and LSH to efficiently identify sequences that are
    similar above a given threshold, then groups them into connected components using
    Union-Find. Two sequences are considered similar if their Jaccard similarity
    (estimated via MinHash) exceeds the threshold.
    """

    def __init__(self, threshold: float = 0.55, num_perm: int = 128):
        """
        Initialize the LSH connected components finder.

        Args:
            threshold: Jaccard similarity threshold. Sequences with similarity above this value will be grouped together.
            num_perm: Number of permutation functions for MinHash. Higher values increase accuracy but also computation time.
        """
        self.threshold = threshold
        self.num_perm = num_perm

    def _get_min_hashes(self, sequences: list[list[str]]) -> list[MinHash]:
        """
        Generate MinHash signatures for all input sequences.
        Converts each sequence of tokens into a MinHash signature that can be used for efficient similarity estimation.

        Args:
            sequences: List of sequences, where each sequence is a list of string tokens

        Returns:
            list[MinHash]: List of MinHash objects, one for each input sequence
        """
        result = []
        for seq in sequences:
            min_hash = MinHash(num_perm=self.num_perm)
            for token in seq:
                min_hash.update(token.encode("utf8"))
            result.append(min_hash)
        return result

    def _get_labels(self, sequences: list[list[str]], u: UnionFind) -> list[int]:
        """
        Convert Union-Find structure to component labels.
        Maps each sequence to its connected component ID. Sequences in the same component will have the same label.

        Args:
            sequences: Original input sequences
            u: Union-Find structure containing the connected components

        Returns:
            list[int]: List of component labels, where sequences[i] belongs to component labels[i]
        """
        components = {}
        labels = []
        next_label = 0
        for idx, _ in enumerate(sequences):
            root = u.find_representative(idx)
            if root not in components:
                components[root] = next_label
                next_label += 1
            labels.append(components[root])

        return labels

    def get_components(self, sequences: list[list[str]]) -> list[int]:
        """
        Find connected components among sequences based on similarity.
        Uses LSH to efficiently identify pairs of sequences with Jaccard similarity above the threshold,
        then groups them into connected components using Union-Find.

        Args:
            sequences: List of sequences to cluster. Each sequence should be a list of string tokens.

        Returns:
            list[int]: Component labels for each sequence. Sequences with the same label belong to the same connected component.
        """
        if not sequences:
            return []

        min_hashes = self._get_min_hashes(sequences)
        lsh = MinHashLSH(threshold=self.threshold, num_perm=self.num_perm)
        for idx, min_hash in enumerate(min_hashes):
            lsh.insert(idx, min_hash)

        u = UnionFind(len(sequences))
        for idx, min_hash in enumerate(min_hashes):
            for similar_idx in lsh.query(min_hash):
                if similar_idx != idx:
                    u.union(idx, similar_idx)

        return self._get_labels(sequences, u)
