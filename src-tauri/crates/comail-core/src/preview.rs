//! Safe in-app attachment previews. Documents are converted to inert data
//! (sanitized HTML, plain text, cell grids) on the Rust side so the webview
//! never runs untrusted parsers or scripts; binaries the frontend renders
//! itself (images, PDFs via pdf.js) are passed through as base64.

use base64::Engine;
use serde::Serialize;
use std::io::{Cursor, Read};

/// Hard cap on the attachment size we will load for preview.
pub const MAX_PREVIEW_BYTES: usize = 25 * 1024 * 1024;
/// Cap on plain-text previews (chars) so a giant log can't stall the UI.
const MAX_TEXT_CHARS: usize = 200_000;
const MAX_SHEETS: usize = 20;
const MAX_ROWS: usize = 1_000;
const MAX_COLS: usize = 64;
const MAX_SLIDES: usize = 200;
/// One aggregate budget of *inflated* bytes shared by every zip entry a
/// document preview reads. Zip 9 already enforces each entry's declared
/// uncompressed size, but nothing capped the total (200 slides x 100 MB).
const MAX_INFLATED_BUDGET: u64 = MAX_PREVIEW_BYTES as u64 * 4;
/// Bound on the summed *declared* inflated size of a spreadsheet container's
/// entries. calamine inflates entries internally where reads can't be
/// metered, so archives whose declared total exceeds this are refused.
const MAX_SHEET_INFLATED: u64 = 128 * 1024 * 1024;
/// Most cells one worksheet's used-range bounding box may span. Dense
/// `Range`s cost rows x cols allocations; beyond this the sheet is refused.
const MAX_SHEET_BBOX: u64 = 2_000_000;
/// Bound on the summed bounding boxes of all sheet substreams in one .xls.
const MAX_SHEET_BBOX_TOTAL: u64 = 8_000_000;
/// `sst/@uniqueCount` bigger than this reserves memory proportional to the
/// claim inside calamine before a single cell is read.
const MAX_SHARED_STRINGS: u64 = 2_000_000;
/// Cells streamed from one sheet reader before the preview truncates;
/// bounds parse time on huge-but-valid worksheets.
const MAX_SCAN_CELLS: usize = 1_000_000;
/// ODS `table:number-*-repeated` expansion bounds, applied to a scanned
/// content.xml before calamine's eager parse.
const MAX_ODS_CELLS: u64 = 4_000_000;
const MAX_ODS_DENSE: u64 = 8_000_000;
/// Cap on produced document-preview output.
const MAX_DOCX_HTML: usize = 500_000;
const MAX_SLIDE_LINES: usize = 5_000;
const MAX_LINE_CHARS: usize = 4_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SheetPreview {
    pub name: String,
    pub rows: Vec<Vec<String>>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlidePreview {
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum AttachmentPreview {
    /// Raster/vector image, delivered as a data URI (rendered in an <img>,
    /// where SVG scripts never execute).
    Image { data_uri: String },
    /// PDF bytes; the frontend rasterizes pages with bundled pdf.js.
    Pdf { base64: String },
    /// Ammonia-sanitized HTML (docx, markdown, html attachments), rendered
    /// inside the same sandboxed iframe used for email bodies.
    Html { html: String },
    /// Spreadsheet / CSV cell grid.
    Sheet { sheets: Vec<SheetPreview> },
    /// Slide-deck text extraction.
    Slides { slides: Vec<SlidePreview> },
    /// Plain text / source code.
    Text { text: String, truncated: bool },
    /// Not previewable in-app; the UI offers "open externally".
    Unsupported { reason: String },
}

/// Build a preview from raw attachment bytes. Never fails: anything we can't
/// parse degrades to `Unsupported` so the UI can fall back to the OS opener.
pub fn build_preview(
    bytes: &[u8],
    filename: Option<&str>,
    mime: Option<&str>,
) -> AttachmentPreview {
    if bytes.len() > MAX_PREVIEW_BYTES {
        return AttachmentPreview::Unsupported {
            reason: "too_large".into(),
        };
    }
    let ext = filename
        .and_then(|f| f.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()))
        .unwrap_or_default();
    let mime = mime.unwrap_or("").to_ascii_lowercase();

    match format_of(&ext, &mime) {
        Format::Image(img_mime) => AttachmentPreview::Image {
            data_uri: format!(
                "data:{};base64,{}",
                img_mime,
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ),
        },
        Format::Pdf => AttachmentPreview::Pdf {
            base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        },
        Format::Docx => docx_preview(bytes),
        Format::Pptx => pptx_preview(bytes),
        Format::Sheet => sheet_preview(bytes),
        Format::Csv(delim) => csv_preview(bytes, delim),
        Format::Markdown => markdown_preview(bytes),
        Format::Html => AttachmentPreview::Html {
            html: crate::mime::sanitize_html(&String::from_utf8_lossy(bytes)),
        },
        Format::Text => text_preview(bytes),
        Format::Unknown => {
            // Heuristic: bytes that decode as valid UTF-8 without control
            // garbage still make a useful text preview (README, LICENSE, ...).
            match std::str::from_utf8(bytes) {
                Ok(s) if !looks_binary(s) => text_preview(bytes),
                _ => AttachmentPreview::Unsupported {
                    reason: "unsupported_type".into(),
                },
            }
        }
    }
}

enum Format {
    Image(&'static str),
    Pdf,
    Docx,
    Pptx,
    Sheet,
    Csv(u8),
    Markdown,
    Html,
    Text,
    Unknown,
}

fn format_of(ext: &str, mime: &str) -> Format {
    match ext {
        "png" => return Format::Image("image/png"),
        "jpg" | "jpeg" => return Format::Image("image/jpeg"),
        "gif" => return Format::Image("image/gif"),
        "webp" => return Format::Image("image/webp"),
        "bmp" => return Format::Image("image/bmp"),
        "svg" => return Format::Image("image/svg+xml"),
        "ico" => return Format::Image("image/x-icon"),
        "avif" => return Format::Image("image/avif"),
        "pdf" => return Format::Pdf,
        "docx" => return Format::Docx,
        "pptx" | "ppsx" => return Format::Pptx,
        "xlsx" | "xlsm" | "xlsb" | "xls" | "ods" => return Format::Sheet,
        "csv" => return Format::Csv(b','),
        "tsv" => return Format::Csv(b'\t'),
        "md" | "markdown" => return Format::Markdown,
        "html" | "htm" => return Format::Html,
        "txt" | "log" | "json" | "xml" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf"
        | "rs" | "py" | "js" | "ts" | "tsx" | "jsx" | "java" | "c" | "cpp" | "h" | "hpp" | "go"
        | "rb" | "sh" | "css" | "sql" | "diff" | "patch" | "ics" | "eml" => return Format::Text,
        _ => {}
    }
    // No (known) extension - fall back to the declared MIME type.
    if let Some(rest) = mime.strip_prefix("image/") {
        // Only image types browsers render; anything else stays unsupported.
        if matches!(
            rest,
            "png" | "jpeg" | "gif" | "webp" | "bmp" | "svg+xml" | "x-icon" | "avif"
        ) {
            return Format::Image(match rest {
                "png" => "image/png",
                "jpeg" => "image/jpeg",
                "gif" => "image/gif",
                "webp" => "image/webp",
                "bmp" => "image/bmp",
                "svg+xml" => "image/svg+xml",
                "x-icon" => "image/x-icon",
                _ => "image/avif",
            });
        }
        return Format::Unknown;
    }
    match mime {
        "application/pdf" => Format::Pdf,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Format::Docx,
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => Format::Pptx,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        | "application/vnd.ms-excel"
        | "application/vnd.oasis.opendocument.spreadsheet" => Format::Sheet,
        "text/csv" => Format::Csv(b','),
        "text/tab-separated-values" => Format::Csv(b'\t'),
        "text/markdown" => Format::Markdown,
        "text/html" => Format::Html,
        m if m.starts_with("text/") => Format::Text,
        "application/json" | "application/xml" => Format::Text,
        _ => Format::Unknown,
    }
}

fn looks_binary(s: &str) -> bool {
    s.chars()
        .take(4096)
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
}

fn text_preview(bytes: &[u8]) -> AttachmentPreview {
    let s = String::from_utf8_lossy(bytes);
    let truncated = s.chars().count() > MAX_TEXT_CHARS;
    AttachmentPreview::Text {
        text: s.chars().take(MAX_TEXT_CHARS).collect(),
        truncated,
    }
}

fn markdown_preview(bytes: &[u8]) -> AttachmentPreview {
    let src: String = String::from_utf8_lossy(bytes)
        .chars()
        .take(MAX_TEXT_CHARS)
        .collect();
    let mut opts = pulldown_cmark::Options::empty();
    opts.insert(pulldown_cmark::Options::ENABLE_TABLES);
    opts.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
    opts.insert(pulldown_cmark::Options::ENABLE_TASKLISTS);
    let parser = pulldown_cmark::Parser::new_ext(&src, opts);
    let mut html = String::new();
    pulldown_cmark::html::push_html(&mut html, parser);
    AttachmentPreview::Html {
        html: crate::mime::sanitize_html(&html),
    }
}

fn csv_preview(bytes: &[u8], delim: u8) -> AttachmentPreview {
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .has_headers(false)
        .flexible(true)
        .from_reader(bytes);
    let mut rows = Vec::new();
    let mut truncated = false;
    for rec in rdr.records() {
        let Ok(rec) = rec else { break };
        if rows.len() >= MAX_ROWS {
            truncated = true;
            break;
        }
        if rec.len() > MAX_COLS {
            truncated = true;
        }
        rows.push(rec.iter().take(MAX_COLS).map(|c| c.to_string()).collect());
    }
    AttachmentPreview::Sheet {
        sheets: vec![SheetPreview {
            name: String::new(),
            rows,
            truncated,
        }],
    }
}

fn sheet_preview(bytes: &[u8]) -> AttachmentPreview {
    // Bound what calamine will allocate *before* handing it the bytes: it
    // inflates zip entries, reserves shared-string capacity, and builds dense
    // grids internally where reads can't be metered from outside.
    if !sheet_preflight_ok(bytes) {
        return unsupported_parse("sheet exceeds preview bounds");
    }
    let mut workbook = match calamine::open_workbook_auto_from_rs(Cursor::new(bytes)) {
        Ok(wb) => wb,
        Err(e) => return unsupported_parse(&e.to_string()),
    };
    use calamine::Reader;
    let names: Vec<String> = workbook.sheet_names().to_vec();
    let mut sheets = Vec::new();
    for name in names.into_iter().take(MAX_SHEETS) {
        let sheet = match &mut workbook {
            // Streamed formats: keep only the cells inside the display window
            // instead of materialising the sheet's whole bounding box.
            calamine::Sheets::Xlsx(wb) => wb.worksheet_cells_reader(&name).ok().map(|mut r| {
                let dims = r.dimensions();
                grid_from_cell_stream(name.clone(), dims, move || r.next_cell().map_err(|_| ()))
            }),
            calamine::Sheets::Xlsb(wb) => wb.worksheet_cells_reader(&name).ok().map(|mut r| {
                let dims = r.dimensions();
                grid_from_cell_stream(name.clone(), dims, move || r.next_cell().map_err(|_| ()))
            }),
            // Dense formats (xls, ods): already bounded by the preflight.
            calamine::Sheets::Xls(wb) => wb
                .worksheet_range(&name)
                .ok()
                .map(|range| grid_from_range(name.clone(), &range)),
            calamine::Sheets::Ods(wb) => wb
                .worksheet_range(&name)
                .ok()
                .map(|range| grid_from_range(name.clone(), &range)),
        };
        if let Some(sheet) = sheet {
            sheets.push(sheet);
        }
    }
    if sheets.is_empty() {
        return unsupported_parse("no sheets");
    }
    AttachmentPreview::Sheet { sheets }
}

fn grid_from_range(name: String, range: &calamine::Range<calamine::Data>) -> SheetPreview {
    let mut rows = Vec::new();
    let mut truncated = false;
    for row in range.rows() {
        if rows.len() >= MAX_ROWS {
            truncated = true;
            break;
        }
        if row.len() > MAX_COLS {
            truncated = true;
        }
        rows.push(
            row.iter()
                .take(MAX_COLS)
                .map(|c| match c {
                    calamine::Data::Empty => String::new(),
                    other => other.to_string(),
                })
                .collect(),
        );
    }
    SheetPreview {
        name,
        rows,
        truncated,
    }
}

/// Bounding-box area of a reported worksheet dimension, in cells. Calamine's
/// own `Dimensions::len` subtracts u32s and underflows when a file declares
/// an inverted range (panic in debug, wrap in release), so the arithmetic is
/// done saturating here: an empty/inverted box reports as tiny.
fn dims_area(d: calamine::Dimensions) -> u64 {
    let rows = u64::from(d.end.0.saturating_sub(d.start.0).saturating_add(1));
    let cols = u64::from(d.end.1.saturating_sub(d.start.1).saturating_add(1));
    rows.saturating_mul(cols)
}

/// Build a preview grid from a streamed cell reader (xlsx / xlsb). The
/// display window anchors on the first real cell, not the declared
/// `<dimension>` start: a missing or stale dimension reports (0,0) and
/// would hide data that actually begins beyond the window. Cells are kept
/// only when their row falls inside the window; columns are trimmed to the
/// narrowest MAX_COLS-wide span covering the first kept column. The scan
/// and the retained set are both bounded, so a dense-bounding-box file
/// can't stall or balloon it.
fn grid_from_cell_stream<'a, E>(
    name: String,
    dims: calamine::Dimensions,
    mut next_cell: impl FnMut() -> Result<Option<calamine::Cell<calamine::DataRef<'a>>>, E>,
) -> SheetPreview {
    /// Retained-cell cap while the column window is still undecided. Far
    /// larger than the MAX_ROWS x MAX_COLS grid ever displayed, so normal
    /// sheets never hit it.
    const MAX_RETAINED: usize = MAX_ROWS * MAX_COLS * 4;
    let mut truncated = dims_area(dims) > MAX_SHEET_BBOX;
    let mut anchor_row: Option<u32> = None;
    let mut cells: std::collections::BTreeMap<(u32, u32), String> = Default::default();
    let mut scanned = 0usize;
    loop {
        let cell = match next_cell() {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(_) => {
                truncated = true;
                break;
            }
        };
        scanned += 1;
        if scanned > MAX_SCAN_CELLS {
            truncated = true;
            break;
        }
        let (r, c) = cell.get_position();
        let ar = *anchor_row.get_or_insert(r);
        // Rows inside the window are kept for the column pass; anything
        // before the anchor row (out-of-order records) or past the window
        // truncates the preview.
        if r >= ar && r < ar.saturating_add(MAX_ROWS as u32) {
            if cells.len() >= MAX_RETAINED {
                truncated = true;
                break;
            }
            let v: calamine::Data = cell.get_value().clone().into();
            let s = v.to_string();
            if !s.is_empty() {
                cells.insert((r, c), s);
            }
        } else {
            truncated = true;
        }
    }
    // Emit contiguous rows through the last kept cell so the grid keeps the
    // same shape the dense-range version produced, anchored at the first
    // real row and column.
    let Some(&(row0, _)) = cells.keys().next() else {
        return SheetPreview {
            name,
            rows: Vec::new(),
            truncated,
        };
    };
    let col0 = cells.keys().map(|&(_, c)| c).min().unwrap_or(0);
    let col_end = col0.saturating_add(MAX_COLS as u32);
    let width = cells
        .keys()
        .filter(|&&(_, c)| c < col_end)
        .map(|&(_, c)| c - col0)
        .max()
        .map_or(0usize, |w| w as usize + 1);
    let mut rows: Vec<Vec<String>> = Vec::new();
    if let Some(&(last_r, _)) = cells.keys().next_back() {
        rows.resize_with((last_r - row0) as usize + 1, Vec::new);
        for ((r, c), s) in cells {
            if c >= col_end {
                truncated = true;
                continue;
            }
            let ri = (r - row0) as usize;
            if rows[ri].is_empty() {
                rows[ri] = vec![String::new(); width];
            }
            rows[ri][(c - col0) as usize] = s;
        }
    }
    SheetPreview {
        name,
        rows,
        truncated,
    }
}

const CFB_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Refuse workbooks that would make calamine allocate outside our bounds
/// before a single sheet is read. All checks run on the raw container.
fn sheet_preflight_ok(bytes: &[u8]) -> bool {
    if bytes.starts_with(CFB_MAGIC) {
        return xls_within_bounds(bytes);
    }
    if !bytes.starts_with(b"PK") {
        // Not a recognised container: auto-detection fails cleanly anyway.
        return true;
    }
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return true;
    };
    // Zip 9 won't produce more bytes than an entry declares, so the summed
    // declared sizes bound everything calamine might inflate internally.
    let mut total = 0u64;
    for i in 0..zip.len() {
        let Ok(f) = zip.by_index(i) else {
            return false;
        };
        total = total.saturating_add(f.size());
        if total > MAX_SHEET_INFLATED {
            return false;
        }
    }
    for i in 0..zip.len() {
        let Ok(f) = zip.by_index(i) else {
            continue;
        };
        let Ok(name) = f.name() else {
            continue;
        };
        if name.ends_with("sharedStrings.xml") {
            // `uniqueCount` drives an eager Vec reserve in calamine.
            let mut head = Vec::new();
            if f.take(64 * 1024).read_to_end(&mut head).is_err() {
                return false;
            }
            if let Some(n) =
                find_subslice(&head, b"uniqueCount").and_then(|p| attr_uint(&head[p..]))
                && n > MAX_SHARED_STRINGS
            {
                return false;
            }
        } else if name.starts_with("xl/worksheets/") && name.ends_with(".xml") {
            // Calamine's dimension parser subtracts u32s and panics on an
            // inverted range ("B5:A1"); screen it before it gets that far.
            let mut head = Vec::new();
            if f.take(64 * 1024).read_to_end(&mut head).is_err() {
                return false;
            }
            if !worksheet_dimensions_ok(&head) {
                return false;
            }
        } else if name == "content.xml" {
            // ODS eagerly expands `number-*-repeated` attributes into a dense
            // grid; a small file can claim billions of cells.
            let mut buf = Vec::new();
            if f.take(MAX_SHEET_INFLATED + 1)
                .read_to_end(&mut buf)
                .is_err()
            {
                return false;
            }
            if !ods_within_bounds(&buf) {
                return false;
            }
        }
    }
    true
}

/// Scan an ODS content.xml for the cell/row totals calamine's eager parser
/// will materialise: real element counts plus `number-*-repeated` expansion,
/// then bound both the sparse cell list and the dense grid built over the
/// per-row column spans. Calamine matches literal `table:` prefixes, so the
/// same literal names are checked here.
fn ods_within_bounds(content: &[u8]) -> bool {
    let mut rows = 0u64;
    let mut rep_rows = 0u64;
    let mut cells = 0u64;
    let mut rep_cols = 0u64;
    let mut cur_row_cells = 0u64;
    let mut max_row_cells = 0u64;
    let mut pos = 0usize;
    while let Some(off) = find_subslice(&content[pos..], b"table:") {
        pos += off;
        let rest = &content[pos..];
        let closing = pos > 0 && content[pos - 1] == b'/';
        let starts = |needle: &[u8]| rest.starts_with(needle) && name_boundary(rest, needle.len());
        if starts(b"table:table-row") {
            if closing {
                max_row_cells = max_row_cells.max(cur_row_cells);
                cur_row_cells = 0;
            } else {
                rows += 1;
            }
        } else if !closing && (starts(b"table:table-cell") || starts(b"table:covered-table-cell")) {
            cells += 1;
            cur_row_cells += 1;
        } else if !closing
            && starts(b"table:number-columns-repeated")
            && let Some(n) = attr_uint(rest)
        {
            rep_cols += n;
            cur_row_cells = cur_row_cells.saturating_add(n.saturating_sub(1));
        } else if !closing
            && starts(b"table:number-rows-repeated")
            && let Some(n) = attr_uint(rest)
        {
            rep_rows += n;
        }
        pos += 6;
    }
    max_row_cells = max_row_cells.max(cur_row_cells);
    if cells.saturating_add(rep_cols) > MAX_ODS_CELLS {
        return false;
    }
    // calamine's MAX_COLUMNS is 16384; the dense grid is bounded by
    // expanded rows x widest row.
    let dense = rows
        .saturating_add(rep_rows)
        .saturating_mul(max_row_cells.min(16_384));
    dense <= MAX_ODS_DENSE
}

/// Bounding-box check for legacy .xls workbooks. `Xls::new` parses every
/// sheet eagerly, so a hostile Workbook stream would materialise the dense
/// grid (or a huge `Vec::reserve` from a crafted DIMENSIONS record) before
/// our code could look at it. Walk the BIFF records ourselves first.
fn xls_within_bounds(bytes: &[u8]) -> bool {
    let Ok(mut cfb) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
        return false;
    };
    let Some(path) = ["/Workbook", "/Book", "Workbook", "Book"]
        .iter()
        .find(|p| cfb.is_stream(p))
    else {
        return false;
    };
    let Ok(stream) = cfb.open_stream(path) else {
        return false;
    };
    // CFB stores the stream uncompressed; it can't exceed the input, but
    // bound the read anyway.
    let mut data = Vec::new();
    stream
        .take(MAX_PREVIEW_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .is_ok()
        && biff_within_bounds(&data)
}

/// Walk BIFF records and bound the used-cell bounding box of each
/// top-level substream (workbook globals, then one per worksheet/chart).
/// Cell-bearing records all carry row u16@0 and col u16@2.
fn biff_within_bounds(data: &[u8]) -> bool {
    const BOF: u16 = 0x0809;
    const EOF: u16 = 0x000A;
    const DIMENSIONS: u16 = 0x0200;
    let mut i = 0usize;
    let mut depth = 0u32;
    let mut total = 0u64;
    let (mut r0, mut r1, mut c0, mut c1) = (u32::MAX, 0u32, u32::MAX, 0u32);
    macro_rules! note {
        ($row:expr, $cf:expr, $cl:expr) => {{
            r0 = r0.min($row);
            r1 = r1.max($row);
            c0 = c0.min($cf);
            c1 = c1.max($cl);
        }};
    }
    macro_rules! close_segment {
        () => {
            if r0 != u32::MAX {
                let area = (r1 - r0 + 1) as u64 * (c1 - c0 + 1) as u64;
                total = total.saturating_add(area);
                if area > MAX_SHEET_BBOX || total > MAX_SHEET_BBOX_TOTAL {
                    return false;
                }
            }
        };
    }
    while i + 4 <= data.len() {
        let typ = u16::from_le_bytes([data[i], data[i + 1]]);
        let len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
        if data.len() - (i + 4) < len {
            break;
        }
        let d = &data[i + 4..i + 4 + len];
        match typ {
            BOF => {
                depth += 1;
                if depth == 1 {
                    r0 = u32::MAX;
                    r1 = 0;
                    c0 = u32::MAX;
                    c1 = 0;
                }
            }
            EOF => {
                if depth == 1 {
                    close_segment!();
                }
                depth = depth.saturating_sub(1);
            }
            DIMENSIONS if depth == 1 => {
                // rf, rl, cf, cl - calamine reserves rl*cl eagerly.
                let dims = match d.len() {
                    14 | 16 => Some((
                        u32::from_le_bytes(d[0..4].try_into().unwrap()),
                        u32::from_le_bytes(d[4..8].try_into().unwrap()),
                        u16::from_le_bytes(d[8..10].try_into().unwrap()) as u32,
                        u16::from_le_bytes(d[10..12].try_into().unwrap()) as u32,
                    )),
                    10 => Some((
                        u16::from_le_bytes(d[0..2].try_into().unwrap()) as u32,
                        u16::from_le_bytes(d[2..4].try_into().unwrap()) as u32,
                        u16::from_le_bytes(d[4..6].try_into().unwrap()) as u32,
                        u16::from_le_bytes(d[6..8].try_into().unwrap()) as u32,
                    )),
                    _ => None,
                };
                if let Some((rf, rl, cf, cl)) = dims {
                    let area = rl.saturating_sub(rf) as u64 * cl.saturating_sub(cf) as u64;
                    total = total.saturating_add(area);
                    if area > MAX_SHEET_BBOX || total > MAX_SHEET_BBOX_TOTAL {
                        return false;
                    }
                }
            }
            // Number, LabelSst, RString, BoolErr, RK, Label, Formula, Blank.
            0x0203 | 0x0204 | 0x00D6 | 0x0205 | 0x027E | 0x00FD | 0x0006 | 0x0201
                if depth == 1 && d.len() >= 4 =>
            {
                let r = u16::from_le_bytes([d[0], d[1]]) as u32;
                let c = u16::from_le_bytes([d[2], d[3]]) as u32;
                note!(r, c, c);
            }
            // MulRk / MulBlank: col range across the record.
            0x00BD | 0x00BE if depth == 1 && d.len() >= 6 => {
                let r = u16::from_le_bytes([d[0], d[1]]) as u32;
                let cf = u16::from_le_bytes([d[2], d[3]]) as u32;
                let cl = u16::from_le_bytes([d[d.len() - 2], d[d.len() - 1]]) as u32;
                note!(r, cf, cl);
            }
            _ => {}
        }
        i += 4 + len;
    }
    if depth == 1 {
        close_segment!();
    }
    true
}

fn unsupported_parse(detail: &str) -> AttachmentPreview {
    tracing::debug!(detail, "attachment preview parse failed");
    AttachmentPreview::Unsupported {
        reason: "parse_failed".into(),
    }
}

/// Resolve an XML entity reference (`&amp;`, `&#233;`, ...) to its text.
/// quick-xml reports these as `GeneralRef` events separate from the text
/// around them. Unknown named entities resolve to None.
pub(crate) fn xml_entity(r: &quick_xml::events::BytesRef) -> Option<String> {
    let name = r.decode().ok()?;
    quick_xml::escape::unescape(&format!("&{name};"))
        .ok()
        .map(|t| t.into_owned())
}

/// Bounded read of one zip entry against a shared inflated-bytes budget.
/// The archive is opened once per preview; `budget` is decremented by what
/// each entry actually produced so the total holds regardless of declared
/// sizes. Returns `(bytes, truncated)`: `truncated` is true when the entry
/// outlived the remaining budget and was cut short, so callers can mark
/// the preview truncated instead of silently accepting half a document.
/// A `None` return means the entry is missing or unreadable.
fn read_entry_bounded<R: Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    idx: usize,
    budget: &mut u64,
) -> Option<(Vec<u8>, bool)> {
    let file = zip.by_index(idx).ok()?;
    let declared = file.size();
    let mut buf = Vec::new();
    file.take(*budget).read_to_end(&mut buf).ok()?;
    *budget = budget.saturating_sub(buf.len() as u64);
    let truncated = (buf.len() as u64) < declared;
    Some((buf, truncated))
}

fn read_entry_bounded_by_name<R: Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    name: &str,
    budget: &mut u64,
) -> Option<(Vec<u8>, bool)> {
    let file = zip.by_name(name).ok()?;
    let declared = file.size();
    let mut buf = Vec::new();
    file.take(*budget).read_to_end(&mut buf).ok()?;
    *budget = budget.saturating_sub(buf.len() as u64);
    let truncated = (buf.len() as u64) < declared;
    Some((buf, truncated))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Byte after `needle` must not continue an XML name, so prefixes like
/// `table:table-row-group` don't count as `table:table-row`.
fn name_boundary(rest: &[u8], needle_len: usize) -> bool {
    match rest.get(needle_len) {
        None => true,
        Some(&b) => !matches!(b, b'-' | b'_' | b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'),
    }
}

/// Check a worksheet's declared `<dimension ref="...">` for an inverted
/// range. Calamine's `get_dimension` computes `end - start` in u32 and
/// panics in debug builds (wraps in release), so an inverted declaration
/// must never reach it. Missing or unparseable dimensions are fine -
/// calamine handles those with an ordinary error path.
fn worksheet_dimensions_ok(xml: &[u8]) -> bool {
    let Some(off) = find_subslice(xml, b"<dimension") else {
        return true;
    };
    if !name_boundary(&xml[off..], "<dimension".len()) {
        return true;
    }
    let end = find_subslice(&xml[off..], b">")
        .map(|e| off + e)
        .unwrap_or(xml.len());
    let tag = &xml[off..end.min(xml.len())];
    let Some(ri) = find_subslice(tag, b"ref") else {
        return true;
    };
    let Some(val) = attr_str(&tag[ri..]) else {
        return true;
    };
    let Ok(val) = std::str::from_utf8(val) else {
        return true;
    };
    let mut parts = val.split(':');
    let Some(first) = cell_ref(parts.next().unwrap_or("")) else {
        return true;
    };
    let last = parts.next().map_or(Some(first), cell_ref).unwrap_or(first);
    last.0 >= first.0 && last.1 >= first.1
}

/// Parse an "A1"-style cell reference into 0-based (row, col). Arithmetic
/// saturates so absurd references can't wrap the indices.
fn cell_ref(rc: &str) -> Option<(u32, u32)> {
    let mut col = 0u32;
    let mut row = 0u32;
    let mut seen_digit = false;
    for b in rc.trim().bytes() {
        match b {
            b'A'..=b'Z' => {
                col = col
                    .saturating_mul(26)
                    .saturating_add(u32::from(b - b'A') + 1)
            }
            b'a'..=b'z' => {
                col = col
                    .saturating_mul(26)
                    .saturating_add(u32::from(b - b'a') + 1)
            }
            b'0'..=b'9' => {
                seen_digit = true;
                row = row.saturating_mul(10).saturating_add(u32::from(b - b'0'));
            }
            b'$' | b' ' => {}
            _ => return None,
        }
    }
    (seen_digit && col > 0).then_some((row.saturating_sub(1), col - 1))
}

/// Parse the quoted string value of an attribute at the start of `rest`
/// (`name="v"` or `name='v'`).
fn attr_str(rest: &[u8]) -> Option<&[u8]> {
    let eq = rest.iter().position(|&b| b == b'=')?;
    let after = &rest[eq + 1..];
    let qpos = after.iter().position(|&b| b == b'"' || b == b'\'')?;
    let q = after[qpos];
    let val = &after[qpos + 1..];
    let end = val.iter().position(|&b| b == q)?;
    Some(&val[..end])
}

/// Parse the integer value of an attribute at the start of `rest`
/// (`name="N"` or `name='N'`).
fn attr_uint(rest: &[u8]) -> Option<u64> {
    let eq = rest.iter().position(|&b| b == b'=')?;
    let after = &rest[eq + 1..];
    let open = after.iter().position(|&b| b == b'"' || b == b'\'')? + 1;
    let digits = &after[open..];
    let end = digits
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&digits[..end]).ok()?.parse().ok()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// DOCX -> simple HTML: paragraphs, Heading styles, list items, and tables.
/// Run-level formatting (bold/italic per run) is intentionally dropped; the
/// goal is a fast, safe, readable preview, not fidelity.
fn docx_preview(bytes: &[u8]) -> AttachmentPreview {
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return unsupported_parse("not a zip");
    };
    let mut budget = MAX_INFLATED_BUDGET;
    let Some((doc, doc_cut)) =
        read_entry_bounded_by_name(&mut zip, "word/document.xml", &mut budget)
    else {
        return unsupported_parse("missing word/document.xml");
    };
    let mut reader = quick_xml::Reader::from_reader(doc.as_slice());
    reader.config_mut().trim_text(false);

    let mut html = String::new();
    let mut para = String::new();
    let mut para_style: Option<String> = None;
    let mut in_list = false;
    let mut numbered = false;
    // Table state: cells accumulate paragraph text; depth guards nesting.
    let mut table_depth = 0usize;
    let mut row: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut buf = Vec::new();
    let mut truncated = false;

    macro_rules! close_list {
        () => {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
        };
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(e)) => match e.local_name().as_ref() {
                b"p" => {
                    para.clear();
                    para_style = None;
                    numbered = false;
                }
                b"tbl" => {
                    table_depth += 1;
                    if table_depth == 1 {
                        close_list!();
                        html.push_str("<table border=\"1\" cellpadding=\"4\">");
                    }
                }
                b"tr" if table_depth == 1 => row.clear(),
                b"tc" if table_depth == 1 => cell.clear(),
                _ => {}
            },
            Ok(quick_xml::events::Event::Empty(e)) => match e.local_name().as_ref() {
                b"pStyle" => {
                    if let Some(v) = attr_val(&e, b"val") {
                        para_style = Some(v);
                    }
                }
                b"numPr" => numbered = true,
                b"br" | b"cr" => para.push('\n'),
                b"tab" => para.push('\t'),
                _ => {}
            },
            Ok(quick_xml::events::Event::Text(t)) => {
                if let Ok(txt) = t.decode() {
                    para.push_str(&txt);
                }
            }
            Ok(quick_xml::events::Event::GeneralRef(r)) => {
                if let Some(txt) = xml_entity(&r) {
                    para.push_str(&txt);
                }
            }
            Ok(quick_xml::events::Event::End(e)) => match e.local_name().as_ref() {
                b"p" => {
                    let text = escape_html(para.trim()).replace('\n', "<br>");
                    if table_depth >= 1 {
                        if !text.is_empty() {
                            if !cell.is_empty() {
                                cell.push_str("<br>");
                            }
                            cell.push_str(&text);
                        }
                    } else if numbered {
                        if !in_list {
                            html.push_str("<ul>");
                            in_list = true;
                        }
                        html.push_str(&format!("<li>{text}</li>"));
                    } else {
                        close_list!();
                        match heading_level(para_style.as_deref()) {
                            Some(level) if !text.is_empty() => {
                                html.push_str(&format!("<h{level}>{text}</h{level}>"));
                            }
                            _ if !text.is_empty() => html.push_str(&format!("<p>{text}</p>")),
                            _ => {}
                        }
                    }
                }
                b"tc" if table_depth == 1 => row.push(std::mem::take(&mut cell)),
                b"tr" if table_depth == 1 => {
                    html.push_str("<tr>");
                    for c in row.drain(..) {
                        html.push_str(&format!("<td>{c}</td>"));
                    }
                    html.push_str("</tr>");
                }
                b"tbl" => {
                    if table_depth == 1 {
                        html.push_str("</table>");
                    }
                    table_depth = table_depth.saturating_sub(1);
                }
                _ => {}
            },
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => {
                // A budget-cut document.xml ends mid-markup: keep whatever
                // parsed and mark it truncated rather than discarding it.
                if doc_cut {
                    truncated = true;
                    break;
                }
                return unsupported_parse("bad document.xml");
            }
            _ => {}
        }
        buf.clear();
        if html.len() + cell.len() + para.len() > MAX_DOCX_HTML {
            truncated = true;
            break;
        }
    }
    if doc_cut {
        truncated = true;
    }
    if truncated {
        if in_list {
            html.push_str("</ul>");
            in_list = false;
        }
        if table_depth > 0 {
            html.push_str("</table>");
        }
        html.push_str("<p>…</p>");
    }
    if in_list {
        html.push_str("</ul>");
    }
    if html.is_empty() {
        return unsupported_parse("empty docx");
    }
    AttachmentPreview::Html {
        html: crate::mime::sanitize_html(&html),
    }
}

fn heading_level(style: Option<&str>) -> Option<u8> {
    let s = style?;
    if s.eq_ignore_ascii_case("title") {
        return Some(1);
    }
    let n = s
        .strip_prefix("Heading")
        .or_else(|| s.strip_prefix("heading"))?
        .parse::<u8>()
        .ok()?;
    (1..=6).contains(&n).then_some(n)
}

fn attr_val(e: &quick_xml::events::BytesStart, name: &[u8]) -> Option<String> {
    e.attributes().flatten().find_map(|a| {
        (a.key.local_name().as_ref() == name).then(|| String::from_utf8_lossy(&a.value).to_string())
    })
}

/// PPTX -> per-slide text lines (each `a:p` paragraph becomes one line).
fn pptx_preview(bytes: &[u8]) -> AttachmentPreview {
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return unsupported_parse("not a zip");
    };
    // Slide entries aren't ordered in the archive; collect and sort by number.
    let mut slide_entries: Vec<(u32, usize)> = (0..zip.len())
        .filter_map(|i| {
            let n: u32 = zip
                .by_index(i)
                .ok()?
                .name()
                .ok()?
                .strip_prefix("ppt/slides/slide")?
                .strip_suffix(".xml")?
                .parse()
                .ok()?;
            Some((n, i))
        })
        .collect();
    slide_entries.sort_unstable();
    if slide_entries.is_empty() {
        return unsupported_parse("no slides");
    }

    let mut budget = MAX_INFLATED_BUDGET;
    let mut truncated = slide_entries.len() > MAX_SLIDES;
    let mut slides = Vec::new();
    let mut total_lines = 0usize;
    for (_, idx) in slide_entries.into_iter().take(MAX_SLIDES) {
        if budget == 0 || total_lines >= MAX_SLIDE_LINES {
            truncated = true;
            break;
        }
        let Some((xml, entry_cut)) = read_entry_bounded(&mut zip, idx, &mut budget) else {
            continue;
        };
        if entry_cut || budget == 0 {
            truncated = true;
        }
        let mut reader = quick_xml::Reader::from_reader(xml.as_slice());
        let mut lines = Vec::new();
        let mut line = String::new();
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Text(t)) => {
                    if let Ok(txt) = t.decode() {
                        line.push_str(&txt);
                    }
                }
                Ok(quick_xml::events::Event::GeneralRef(r)) => {
                    if let Some(txt) = xml_entity(&r) {
                        line.push_str(&txt);
                    }
                }
                Ok(quick_xml::events::Event::End(e)) if e.local_name().as_ref() == b"p" => {
                    let mut trimmed = line.trim().to_string();
                    line.clear();
                    if !trimmed.is_empty() {
                        if trimmed.chars().count() > MAX_LINE_CHARS {
                            trimmed = trimmed.chars().take(MAX_LINE_CHARS).collect();
                            truncated = true;
                        }
                        lines.push(trimmed);
                    }
                }
                Ok(quick_xml::events::Event::Eof) => break,
                Err(_) => break,
                _ => {}
            }
            buf.clear();
            if total_lines + lines.len() >= MAX_SLIDE_LINES {
                truncated = true;
                break;
            }
        }
        total_lines += lines.len();
        slides.push(SlidePreview { lines });
    }
    if truncated {
        slides.push(SlidePreview {
            lines: vec!["…".into()],
        });
    }
    AttachmentPreview::Slides { slides }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_with(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, content) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(content.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn image_becomes_data_uri() {
        let p = build_preview(&[0x89, 0x50, 0x4e, 0x47], Some("pic.PNG"), None);
        match p {
            AttachmentPreview::Image { data_uri } => {
                assert!(data_uri.starts_with("data:image/png;base64,"))
            }
            other => panic!("expected image, got {other:?}"),
        }
    }

    #[test]
    fn pdf_passes_base64() {
        let p = build_preview(b"%PDF-1.7", None, Some("application/pdf"));
        assert!(matches!(p, AttachmentPreview::Pdf { .. }));
    }

    #[test]
    fn markdown_renders_sanitized_html() {
        let p = build_preview(
            b"# Hi\n\n*em*\n\n<script>alert(1)</script>",
            Some("readme.md"),
            None,
        );
        match p {
            AttachmentPreview::Html { html } => {
                assert!(html.contains("<h1>Hi</h1>"));
                assert!(html.contains("<em>em</em>"));
                assert!(!html.contains("script"));
            }
            other => panic!("expected html, got {other:?}"),
        }
    }

    #[test]
    fn html_attachment_is_sanitized() {
        let p = build_preview(
            b"<p onclick=\"x()\">ok</p><script>bad()</script>",
            Some("page.html"),
            None,
        );
        match p {
            AttachmentPreview::Html { html } => {
                assert!(html.contains("<p>ok</p>"));
                assert!(!html.contains("onclick") && !html.contains("script"));
            }
            other => panic!("expected html, got {other:?}"),
        }
    }

    #[test]
    fn csv_parses_grid() {
        let p = build_preview(b"a,b,\"c,d\"\n1,2,3\n", Some("data.csv"), None);
        match p {
            AttachmentPreview::Sheet { sheets } => {
                assert_eq!(sheets[0].rows[0], vec!["a", "b", "c,d"]);
                assert_eq!(sheets[0].rows[1], vec!["1", "2", "3"]);
            }
            other => panic!("expected sheet, got {other:?}"),
        }
    }

    #[test]
    fn docx_paragraphs_headings_tables() {
        const DOC: &str = r#"<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body>
  <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Title</w:t></w:r></w:p>
  <w:p><w:r><w:t>Hello </w:t></w:r><w:r><w:t>world &amp; &lt;tag&gt;</w:t></w:r></w:p>
  <w:p><w:pPr><w:numPr/></w:pPr><w:r><w:t>item one</w:t></w:r></w:p>
  <w:tbl><w:tr><w:tc><w:p><w:r><w:t>A1</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>B1</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
 </w:body>
</w:document>"#;
        let bytes = zip_with(&[("word/document.xml", DOC)]);
        let p = build_preview(&bytes, Some("doc.docx"), None);
        match p {
            AttachmentPreview::Html { html } => {
                assert!(html.contains("<h1>Title</h1>"), "html: {html}");
                assert!(
                    html.contains("<p>Hello world &amp; &lt;tag&gt;</p>"),
                    "html: {html}"
                );
                assert!(html.contains("<li>item one</li>"), "html: {html}");
                assert!(html.contains("<td>A1</td><td>B1</td>"), "html: {html}");
            }
            other => panic!("expected html, got {other:?}"),
        }
    }

    #[test]
    fn pptx_extracts_slide_lines_in_order() {
        const S: &str = r#"<?xml version="1.0"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
 <p:cSld><p:spTree><p:sp><p:txBody>
   <a:p><a:r><a:t>SLIDE_TXT</a:t></a:r></a:p>
 </p:txBody></p:sp></p:spTree></p:cSld>
</p:sld>"#;
        let bytes = zip_with(&[
            ("ppt/slides/slide2.xml", &S.replace("SLIDE_TXT", "second")),
            ("ppt/slides/slide1.xml", &S.replace("SLIDE_TXT", "first")),
        ]);
        let p = build_preview(&bytes, Some("deck.pptx"), None);
        match p {
            AttachmentPreview::Slides { slides } => {
                assert_eq!(slides.len(), 2);
                assert_eq!(slides[0].lines, vec!["first"]);
                assert_eq!(slides[1].lines, vec!["second"]);
            }
            other => panic!("expected slides, got {other:?}"),
        }
    }

    #[test]
    fn unknown_binary_is_unsupported_but_utf8_previews_as_text() {
        let p = build_preview(&[0u8, 159, 146, 150], Some("blob.bin"), None);
        assert!(matches!(p, AttachmentPreview::Unsupported { .. }));
        let p = build_preview(b"plain readme contents", Some("LICENSE"), None);
        assert!(matches!(p, AttachmentPreview::Text { .. }));
    }

    #[test]
    fn oversized_is_rejected() {
        let p = build_preview(&vec![0u8; MAX_PREVIEW_BYTES + 1], Some("big.pdf"), None);
        match p {
            AttachmentPreview::Unsupported { reason } => assert_eq!(reason, "too_large"),
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn text_truncates() {
        let big = "x".repeat(MAX_TEXT_CHARS + 10);
        let p = build_preview(big.as_bytes(), Some("big.log"), None);
        match p {
            AttachmentPreview::Text { text, truncated } => {
                assert!(truncated);
                assert_eq!(text.chars().count(), MAX_TEXT_CHARS);
            }
            other => panic!("expected text, got {other:?}"),
        }
    }

    // ---- decompression/allocation-bomb hardening -------------------------

    fn zip_with_raw(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, content) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(content).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    /// Minimal xlsx skeleton calamine can open, with `sheet_xml` as Sheet1.
    fn xlsx_with_sheet(sheet_xml: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
        const RELS: &str = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;
        const WORKBOOK: &str = r#"<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
        const WB_RELS: &str = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"#;
        let mut entries: Vec<(&str, &[u8])> = vec![
            ("_rels/.rels", RELS.as_bytes()),
            ("xl/workbook.xml", WORKBOOK.as_bytes()),
            ("xl/_rels/workbook.xml.rels", WB_RELS.as_bytes()),
            ("xl/worksheets/sheet1.xml", sheet_xml.as_bytes()),
        ];
        entries.extend_from_slice(extra);
        zip_with_raw(&entries)
    }

    #[test]
    fn xlsx_far_apart_cells_preview_bounded() {
        // A1 + XFD1048576: a dense grid over this bounding box would need
        // ~17 billion cells; the streamed reader must not build it.
        const SHEET: &str = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<dimension ref="A1:XFD1048576"/><sheetData>
<row r="1"><c r="A1"><v>1</v></c><c r="XFD1048576"><v>2</v></c></row>
</sheetData></worksheet>"#;
        let bytes = xlsx_with_sheet(SHEET, &[]);
        let p = build_preview(&bytes, Some("bomb.xlsx"), None);
        match p {
            AttachmentPreview::Sheet { sheets } => {
                assert_eq!(sheets.len(), 1);
                assert!(sheets[0].truncated, "extreme bbox must flag truncation");
                assert_eq!(sheets[0].rows[0][0], "1");
                assert!(sheets[0].rows.len() <= MAX_ROWS);
                assert!(sheets[0].rows.iter().all(|r| r.len() <= MAX_COLS));
            }
            other => panic!("expected sheet, got {other:?}"),
        }
    }

    #[test]
    fn xlsx_normal_sheet_streams() {
        const SHEET: &str = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="1"><c r="A1"><v>1</v></c><c r="B1"><v>2</v></c></row>
<row r="3"><c r="A3" t="inlineStr"><is><t>hi</t></is></c></row>
</sheetData></worksheet>"#;
        let bytes = xlsx_with_sheet(SHEET, &[]);
        let p = build_preview(&bytes, Some("ok.xlsx"), None);
        match p {
            AttachmentPreview::Sheet { sheets } => {
                assert_eq!(sheets[0].name, "Sheet1");
                assert_eq!(sheets[0].rows[0], vec!["1", "2"]);
                assert_eq!(sheets[0].rows[2][0], "hi");
                assert!(!sheets[0].truncated);
            }
            other => panic!("expected sheet, got {other:?}"),
        }
    }

    #[test]
    fn xlsx_absurd_shared_strings_claim_rejected() {
        const SST: &str = r#"<?xml version="1.0"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="99999999"><si><t>x</t></si></sst>"#;
        const SHEET: &str = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row r="1"><c r="A1"><v>1</v></c></row></sheetData></worksheet>"#;
        let bytes = xlsx_with_sheet(SHEET, &[("xl/sharedStrings.xml", SST.as_bytes())]);
        assert!(matches!(
            build_preview(&bytes, Some("bomb.xlsx"), None),
            AttachmentPreview::Unsupported { .. }
        ));
    }

    #[test]
    fn xlsx_without_dimension_anchors_on_first_real_cell() {
        // No <dimension> element: calamine reports start (0,0), so a window
        // anchored there shows an empty grid for data that actually starts
        // at row 5000. The window must follow the first streamed cell.
        const SHEET: &str = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="5000"><c r="B5000"><v>7</v></c><c r="C5000"><v>8</v></c></row>
<row r="5002"><c r="B5002"><v>9</v></c></row>
</sheetData></worksheet>"#;
        let bytes = xlsx_with_sheet(SHEET, &[]);
        let p = build_preview(&bytes, Some("nodim.xlsx"), None);
        match p {
            AttachmentPreview::Sheet { sheets } => {
                assert_eq!(sheets[0].rows[0], vec!["7", "8"]);
                assert_eq!(sheets[0].rows[2][0], "9");
            }
            other => panic!("expected sheet, got {other:?}"),
        }
    }

    #[test]
    fn xlsx_inverted_dimension_is_refused_not_panicked() {
        // "B5:A1" parses to start > end; calamine's get_dimension subtracts
        // in u32 and panics (debug) / wraps (release), so the preflight
        // refuses the file instead of ever handing it the dimension.
        const SHEET: &str = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<dimension ref="B5:A1"/><sheetData>
<row r="5"><c r="B5"><v>4</v></c></row>
</sheetData></worksheet>"#;
        let bytes = xlsx_with_sheet(SHEET, &[]);
        assert!(matches!(
            build_preview(&bytes, Some("inv.xlsx"), None),
            AttachmentPreview::Unsupported { .. }
        ));
        // A normal single-cell and a sane range still pass the check.
        assert!(worksheet_dimensions_ok(b"<dimension ref=\"B5\"/>"));
        assert!(worksheet_dimensions_ok(b"<dimension ref=\"A1:XFD10\"/>"));
        assert!(!worksheet_dimensions_ok(b"<dimension ref=\"B5:A1\"/>"));
        // ...and a column-only inversion is caught too.
        assert!(!worksheet_dimensions_ok(b"<dimension ref=\"C1:A5\"/>"));
    }

    #[test]
    fn ods_repeat_bomb_rejected() {
        // 1000 rows x 16384 repeated cells claims ~16M expanded cells.
        let mut content = String::from(
            r#"<?xml version="1.0"?>
<office:document-content xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
<office:body><office:spreadsheet><table:table table:name="S">"#,
        );
        for _ in 0..1000 {
            content.push_str(
                r#"<table:table-row><table:table-cell table:number-columns-repeated="16384" office:value="1"/></table:table-row>"#,
            );
        }
        content.push_str(
            "</table:table></office:spreadsheet></office:body></office:document-content>",
        );
        let bytes = zip_with_raw(&[
            (
                "mimetype",
                b"application/vnd.oasis.opendocument.spreadsheet".as_slice(),
            ),
            ("content.xml", content.as_bytes()),
        ]);
        assert!(matches!(
            build_preview(&bytes, Some("bomb.ods"), None),
            AttachmentPreview::Unsupported { .. }
        ));
    }

    #[test]
    fn biff_bounds_accept_small_and_refuse_huge() {
        fn rec(typ: u16, data: &[u8]) -> Vec<u8> {
            let mut v = typ.to_le_bytes().to_vec();
            v.extend_from_slice(&(data.len() as u16).to_le_bytes());
            v.extend_from_slice(data);
            v
        }
        let bof = rec(0x0809, &[0; 8]);
        let eof = rec(0x000A, &[]);
        let number = |r: u16, c: u16| {
            let mut d = r.to_le_bytes().to_vec();
            d.extend_from_slice(&c.to_le_bytes());
            d.extend_from_slice(&[0; 10]);
            rec(0x0203, &d)
        };
        // Two cells 5 rows apart: fine.
        let mut ok = [bof.clone(), number(0, 0), number(5, 3), eof.clone()].concat();
        assert!(biff_within_bounds(&ok));
        // A cell near the format edge: the dense grid would be ~17M cells.
        let mut far = [bof.clone(), number(0, 0), number(65000, 255), eof.clone()].concat();
        assert!(!biff_within_bounds(&far));
        // A DIMENSIONS record claiming a giant range drives an eager reserve.
        let mut dims = 0u32.to_le_bytes().to_vec();
        dims.extend_from_slice(&1_000_000u32.to_le_bytes());
        dims.extend_from_slice(&0u16.to_le_bytes());
        dims.extend_from_slice(&16_384u16.to_le_bytes());
        dims.extend_from_slice(&[0; 2]);
        ok = [bof.clone(), rec(0x0200, &dims), eof.clone()].concat();
        assert!(!biff_within_bounds(&ok));
        // Same claim in a BIFF5-era 10-byte record.
        let mut dims5 = 0u16.to_le_bytes().to_vec();
        dims5.extend_from_slice(&60_000u16.to_le_bytes());
        dims5.extend_from_slice(&0u16.to_le_bytes());
        dims5.extend_from_slice(&255u16.to_le_bytes());
        dims5.extend_from_slice(&[0; 2]);
        far = [bof.clone(), rec(0x0200, &dims5), eof.clone()].concat();
        assert!(!biff_within_bounds(&far));
    }

    #[test]
    fn pptx_many_compressible_slides_stay_bounded() {
        // 25 slides, each ~8 MB inflated of one repeated char: 200 MB total,
        // over the 100 MB aggregate budget.
        let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 1..=25 {
            let mut slide = String::from(
                r#"<?xml version="1.0"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>"#,
            );
            slide.push_str(&"x".repeat(8 * 1024 * 1024));
            slide.push_str("</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>");
            entries.push((format!("ppt/slides/slide{i}.xml"), slide.into_bytes()));
        }
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, content) in &entries {
            w.start_file(name.as_str(), zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(content).unwrap();
        }
        let bytes = w.finish().unwrap().into_inner();
        assert!(bytes.len() < 20 * 1024 * 1024, "test zip must stay small");
        let p = build_preview(&bytes, Some("deck.pptx"), None);
        match p {
            AttachmentPreview::Slides { slides } => {
                assert!(slides.len() <= MAX_SLIDES + 1);
                let total: usize = slides.iter().map(|s| s.lines.len()).sum();
                assert!(total <= MAX_SLIDE_LINES + 1);
                // Truncation marker slide is last.
                assert_eq!(slides.last().unwrap().lines, vec!["…".to_string()]);
                for s in &slides[..slides.len() - 1] {
                    assert!(s.lines.iter().all(|l| l.len() <= MAX_LINE_CHARS));
                }
            }
            other => panic!("expected slides, got {other:?}"),
        }
    }

    #[test]
    fn docx_output_is_capped() {
        // ~60k short paragraphs inflate to a few MB - small zip, but the
        // produced HTML would exceed the cap and must truncate instead.
        let mut doc = String::from(
            r#"<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
        );
        for i in 0..60_000 {
            doc.push_str("<w:p><w:r><w:t>para ");
            doc.push_str(&i.to_string());
            doc.push_str("</w:t></w:r></w:p>");
        }
        doc.push_str("</w:body></w:document>");
        let bytes = zip_with_raw(&[("word/document.xml", doc.as_bytes())]);
        let p = build_preview(&bytes, Some("big.docx"), None);
        match p {
            AttachmentPreview::Html { html } => {
                assert!(
                    html.len() <= MAX_DOCX_HTML + 2048,
                    "html {} over cap",
                    html.len()
                );
                assert!(html.contains('…'), "missing truncation marker");
            }
            other => panic!("expected html, got {other:?}"),
        }
    }
}
