package scheduler

import (
	"time"

	"github.com/herbiewalker/sanctum/internal/index"
)

func vaultOwner(id, label string, now time.Time) index.Owner {
	return index.Owner{
		ID: id, Label: label, LoginUsername: label,
		CreatedAt: now.Unix(),
	}
}

func vaultOwnerAuth() index.OwnerAuth {
	return index.OwnerAuth{
		KDF: "pbkdf2-sha256", Salt: []byte{1}, Iterations: 1, Hash: []byte{1},
	}
}

func vaultPassword(id, ownerID, pw string, now time.Time) index.BackupPassword {
	return index.BackupPassword{
		ID: id, OwnerID: ownerID, Label: "primary",
		Passphrase: []byte(pw), AddedAt: now.Unix(),
	}
}

func vaultBackup(id, ownerID, sha string, size, ingestedAt int64, iters int, pwID *string) index.Backup {
	return index.Backup{
		ID: id, OwnerID: ownerID, SHA256: sha, SizeBytes: size,
		IngestedAt: ingestedAt, Source: "inbox",
		ContainerVersion: 1, KDFIterations: iters,
		VerifyStatus: "unverified", OpenedByPasswordID: pwID,
		BlobPath: ownerID + "/" + id + ".tryst",
	}
}
