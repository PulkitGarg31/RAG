import io
import zipfile

import httpx
import respx

from vt.ingest.osv import OSV_ALL_ZIP_URL, download_all_zip


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("GHSA-x.json", "{}")
    return buf.getvalue()


@respx.mock
def test_download_reuses_fresh_complete_zip_without_network(tmp_path):
    dest = tmp_path / "all.zip"
    dest.write_bytes(_zip_bytes())
    # respx.mock with no routes: any HTTP request would raise.
    assert download_all_zip(dest) == dest


@respx.mock
def test_download_replaces_truncated_cached_zip(tmp_path):
    dest = tmp_path / "all.zip"
    dest.write_bytes(_zip_bytes()[:10])  # fresh mtime, but truncated
    respx.get(OSV_ALL_ZIP_URL).mock(return_value=httpx.Response(200, content=_zip_bytes()))

    download_all_zip(dest)

    with zipfile.ZipFile(dest) as zf:
        assert zf.namelist() == ["GHSA-x.json"]
    assert not (tmp_path / "all.zip.part").exists()
