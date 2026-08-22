# Mutable-marker source snapshots

`commit-a/action.yml` and `commit-b/action.yml` are source trees to commit in a
disposable Action repository. Their directory names describe roles, not Git
object IDs. The online lab must record the actual full commit IDs Git creates.

The repeated `a` and `b` object IDs in the offline corpus are obvious synthetic
sentinels. They are not the hashes of these files and must never be copied into a
real incident pack.
