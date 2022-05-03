/*
 * Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#define G_LOG_DOMAIN "FuArchive"

#include "config.h"

#include <gio/gio.h>

#ifdef HAVE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif

#include "fwupd-error.h"

#include "fu-archive.h"

/**
 * FuArchive:
 *
 * An in-memory archive decompressor
 */

struct _FuArchive {
	GObject parent_instance;
	GHashTable *entries;
	gpointer ctx;
	GByteArray *blob;
};

G_DEFINE_TYPE(FuArchive, fu_archive, G_TYPE_OBJECT)

static void
fu_archive_finalize(GObject *obj)
{
	FuArchive *self = FU_ARCHIVE(obj);

	g_hash_table_unref(self->entries);
	G_OBJECT_CLASS(fu_archive_parent_class)->finalize(obj);
}

static void
fu_archive_class_init(FuArchiveClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = fu_archive_finalize;
}

static void
fu_archive_init(FuArchive *self)
{
	self->entries =
	    g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_bytes_unref);
}

/**
 * fu_archive_lookup_by_fn:
 * @self: a #FuArchive
 * @fn: a filename
 * @error: (nullable): optional return location for an error
 *
 * Finds the blob referenced by filename
 *
 * Returns: (transfer none): a #GBytes, or %NULL if the filename was not found
 *
 * Since: 1.2.2
 **/
GBytes *
fu_archive_lookup_by_fn(FuArchive *self, const gchar *fn, GError **error)
{
	GBytes *bytes;

	g_return_val_if_fail(FU_IS_ARCHIVE(self), NULL);
	g_return_val_if_fail(fn != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	bytes = g_hash_table_lookup(self->entries, fn);
	if (bytes == NULL) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "no blob for %s", fn);
	}
	return bytes;
}

/**
 * fu_archive_iterate:
 * @self: a #FuArchive
 * @callback: a #FuArchiveIterateFunc.
 * @user_data: user data
 * @error: (nullable): optional return location for an error
 *
 * Iterates over the archive contents, calling the given function for each
 * of the files found. If any @callback returns %FALSE scanning is aborted.
 *
 * Returns: True if no @callback returned FALSE
 *
 * Since: 1.3.4
 */
gboolean
fu_archive_iterate(FuArchive *self,
		   FuArchiveIterateFunc callback,
		   gpointer user_data,
		   GError **error)
{
	GHashTableIter iter;
	gpointer key, value;

	g_return_val_if_fail(FU_IS_ARCHIVE(self), FALSE);
	g_return_val_if_fail(callback != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_hash_table_iter_init(&iter, self->entries);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		if (!callback(self, (const gchar *)key, (GBytes *)value, user_data, error))
			return FALSE;
	}
	return TRUE;
}

#ifdef HAVE_LIBARCHIVE
/* workaround the struct types of libarchive */
typedef struct archive _archive_read_ctx;

static void
_archive_read_ctx_free(_archive_read_ctx *arch)
{
	archive_read_close(arch);
	archive_read_free(arch);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(_archive_read_ctx, _archive_read_ctx_free)

typedef struct archive _archive_write_ctx;

static void
_archive_write_ctx_free(_archive_write_ctx *arch)
{
	archive_write_close(arch);
	archive_write_free(arch);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(_archive_write_ctx, _archive_write_ctx_free)

typedef struct archive_entry _archive_entry_ctx;

static void
_archive_entry_ctx_free(_archive_entry_ctx *entry)
{
	archive_entry_free(entry);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(_archive_entry_ctx, _archive_entry_ctx_free)
#endif

static gboolean
fu_archive_load(FuArchive *self, GBytes *blob, FuArchiveFlags flags, GError **error)
{
#ifdef HAVE_LIBARCHIVE
	int r;
	g_autoptr(_archive_read_ctx) arch = NULL;

	/* decompress anything matching either glob */
	arch = archive_read_new();
	if (arch == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_NOT_SUPPORTED,
				    "libarchive startup failed");
		return FALSE;
	}
	archive_read_support_format_all(arch);
	archive_read_support_filter_all(arch);
	r = archive_read_open_memory(arch,
				     (void *)g_bytes_get_data(blob, NULL),
				     (size_t)g_bytes_get_size(blob));
	if (r != 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_NOT_SUPPORTED,
			    "cannot open: %s",
			    archive_error_string(arch));
		return FALSE;
	}
	while (TRUE) {
		const gchar *fn = NULL;
		gint64 bufsz;
		gssize rc;
		struct archive_entry *entry;
		g_autofree gchar *fn_key = NULL;
		g_autofree guint8 *buf = NULL;

		r = archive_read_next_header(arch, &entry);
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot read header: %s",
				    archive_error_string(arch));
			return FALSE;
		}

		/* only extract if valid */
		fn = archive_entry_pathname(entry);
		if (fn == NULL)
			continue;
		bufsz = archive_entry_size(entry);
		if (bufsz > 1024 * 1024 * 1024) {
			g_set_error_literal(error,
					    G_IO_ERROR,
					    G_IO_ERROR_FAILED,
					    "cannot read huge files");
			return FALSE;
		}
		buf = g_malloc(bufsz);
		rc = archive_read_data(arch, buf, (gsize)bufsz);
		if (rc < 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot read data: %s",
				    archive_error_string(arch));
			return FALSE;
		}
		if (rc != bufsz) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "read %" G_GSSIZE_FORMAT " of %" G_GINT64_FORMAT,
				    rc,
				    bufsz);
			return FALSE;
		}
		if (flags & FU_ARCHIVE_FLAG_IGNORE_PATH) {
			fn_key = g_path_get_basename(fn);
		} else {
			fn_key = g_strdup(fn);
		}
		g_debug("adding %s [%" G_GINT64_FORMAT "]", fn_key, bufsz);
		g_hash_table_insert(self->entries,
				    g_steal_pointer(&fn_key),
				    g_bytes_new_take(g_steal_pointer(&buf), bufsz));
	}

	/* success */
	return TRUE;
#else
	g_set_error_literal(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "missing libarchive support");
	return FALSE;
#endif
}

static GByteArray *
fu_archive_save(FuArchive *self,
		const gchar *compress,
		FuArchiveEntryIterateFunc callback,
		gpointer user_data,
		GError **error)
{
#ifdef HAVE_LIBARCHIVE
	const gchar *fn;
	gsize blobsz;
	size_t size;
	int r;
	g_autoptr(GByteArray) blob = NULL;
	g_autoptr(_archive_write_ctx) arch = NULL;

	blobsz = 0x20000;
	blob = g_byte_array_sized_new(blobsz);

	/* compress anything matching either glob */
	arch = archive_write_new();
	if (arch == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_NOT_SUPPORTED,
				    "libarchive startup failed");
		return NULL;
	}
	archive_write_add_filter_by_name(arch, compress);
	archive_write_set_format_pax_restricted(arch);
	r = archive_write_open_memory(arch, blob->data, blobsz, &size);
	if (r != 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_NOT_SUPPORTED,
			    "cannot open: %s",
			    archive_error_string(arch));
		return NULL;
	}

	while (TRUE) {
		GBytes *bytes;
		gint64 bufsz;
		const guint8 *buf;
		ssize_t rc;
		g_autoptr(_archive_entry_ctx) entry = NULL;

		bytes = callback(self, &fn, user_data, error);
		if (bytes == NULL)
			return NULL;

		buf = g_bytes_get_data(bytes, NULL);
		bufsz = g_bytes_get_size(bytes);

		if (fn == NULL)
			break;

		entry = archive_entry_new();
		archive_entry_set_pathname(entry, fn);
		archive_entry_set_filetype(entry, AE_IFREG);
		archive_entry_set_perm(entry, 0644);
		archive_entry_set_size(entry, bufsz);

		r = archive_write_header(arch, entry);
		if (r != 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_NOT_SUPPORTED,
				    "cannot write header: %s",
				    archive_error_string(arch));
			return NULL;
		}

		rc = archive_write_data(arch, buf, bufsz);
		if (rc < 0) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "cannot write data: %s",
				    archive_error_string(arch));
			return NULL;
		}
		if (rc != bufsz) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "write %" G_GSSIZE_FORMAT " of %" G_GINT64_FORMAT,
				    rc,
				    bufsz);
			return NULL;
		}
	}

	r = archive_write_close(arch);
	if (r != 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_NOT_SUPPORTED,
			    "cannot close: %s",
			    archive_error_string(arch));
		return NULL;
	}

	/* success */
	g_byte_array_set_size(blob, size); /* FIXME: is it correct? */
	return g_steal_pointer(&blob);
#else
	g_set_error_literal(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "missing libarchive support");
	return FALSE;
#endif
}

/**
 * fu_archive_new:
 *
 * TODO
 *
 * Since: 1.8.1
 **/
FuArchive *
fu_archive_new(void)
{
	g_autoptr(FuArchive) self = g_object_new(FU_TYPE_ARCHIVE, NULL);
	return g_steal_pointer(&self);
}

/**
 * fu_archive_new_from_bytes:
 * @data: archive contents
 * @flags: archive flags, e.g. %FU_ARCHIVE_FLAG_NONE
 * @error: (nullable): optional return location for an error
 *
 * Parses @data as an archive and decompresses all files to memory blobs.
 *
 * Returns: a #FuArchive, or %NULL if the archive was invalid in any way.
 *
 * Since: 1.2.2
 **/
FuArchive *
fu_archive_new_from_bytes(GBytes *data, FuArchiveFlags flags, GError **error)
{
	g_autoptr(FuArchive) self = g_object_new(FU_TYPE_ARCHIVE, NULL);
	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);
	if (!fu_archive_load(self, data, flags, error))
		return NULL;
	return g_steal_pointer(&self);
}

/**
 * fu_archive_get_bytes:
 * @callback: a #FuArchiveEntryIterateFunc.
 * @user_data: user data
 * @error: (nullable): optional return location for an error
 *
 * TODO
 *
 * Since: 1.8.1
 **/
GBytes *
fu_archive_get_bytes(FuArchive *self,
		     const gchar *compress,
		     FuArchiveEntryIterateFunc callback,
		     gpointer user_data,
		     GError **error)
{
	g_autoptr(GByteArray) data = NULL;
	g_return_val_if_fail(callback != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);
	data = fu_archive_save(self, compress, callback, user_data, error);
	if (data == NULL)
		return NULL;
	return g_byte_array_free_to_bytes(g_steal_pointer(&data));
}
