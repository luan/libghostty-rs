#[cfg(fuzzing)]
use afl::fuzz;
use libghostty_vt::{
    RenderState, Terminal, TerminalOptions,
    render::{CellIterator, RowIterator},
};
#[cfg(not(fuzzing))]
use std::io::Read;
use std::sync::OnceLock;

const OPTION_BYTES: usize = 5;
const MAX_TERMINAL_COLS_BYTE: u8 = 160;
const MAX_TERMINAL_ROWS_BYTE: u8 = 64;
const SCROLLBACK_MULTIPLIER: usize = 4;
const MAX_APC_BYTES: usize = 64 * 1024;
const CELL_WIDTH_PX: u32 = 8;
const CELL_HEIGHT_PX: u32 = 16;

// Optional env-var overrides for stress runs. When set, the corresponding
// dimension byte from the input is ignored and every iteration uses the
// pinned value. Parsed once at startup; AFL invokes fuzz_terminal millions
// of times so we cannot afford a getenv + parse per call.
const ENV_FORCE_COLS: &str = "LIBGHOSTTY_FUZZ_COLS";
const ENV_FORCE_ROWS: &str = "LIBGHOSTTY_FUZZ_ROWS";

fn forced_cols() -> Option<u16> {
    static CACHE: OnceLock<Option<u16>> = OnceLock::new();
    *CACHE.get_or_init(|| parse_dimension_env(ENV_FORCE_COLS))
}

fn forced_rows() -> Option<u16> {
    static CACHE: OnceLock<Option<u16>> = OnceLock::new();
    *CACHE.get_or_init(|| parse_dimension_env(ENV_FORCE_ROWS))
}

fn parse_dimension_env(name: &str) -> Option<u16> {
    let raw = std::env::var(name).ok()?;
    let value: u16 = raw
        .parse()
        .unwrap_or_else(|err| panic!("{name} must be a u16 (1..=65535): {err}"));
    assert!(value > 0, "{name} must be > 0");
    Some(value)
}

#[cfg(fuzzing)]
fn main() {
    fuzz!(|data: &[u8]| {
        fuzz_terminal(data);
    });
}

#[cfg(not(fuzzing))]
fn main() -> std::io::Result<()> {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;
    fuzz_terminal(&data);
    Ok(())
}

fn fuzz_terminal(data: &[u8]) {
    if data.len() < OPTION_BYTES {
        return;
    }

    let options = terminal_options(data);
    let Ok(mut terminal) = Terminal::new(options) else {
        return;
    };

    if terminal.set_apc_max_bytes(Some(MAX_APC_BYTES)).is_err() {
        return;
    }
    if install_effect_handlers(&mut terminal).is_err() {
        return;
    }

    let payload = &data[OPTION_BYTES..];
    let split = payload.len() / 2;
    terminal.vt_write(&payload[..split]);

    let resize_cols = forced_cols().unwrap_or_else(|| dimension(data[3], MAX_TERMINAL_COLS_BYTE));
    let resize_rows = forced_rows().unwrap_or_else(|| dimension(data[4], MAX_TERMINAL_ROWS_BYTE));
    let _resize_result = terminal.resize(resize_cols, resize_rows, CELL_WIDTH_PX, CELL_HEIGHT_PX);

    terminal.vt_write(&payload[split..]);
    exercise_rendering(&terminal);
}

fn terminal_options(data: &[u8]) -> TerminalOptions {
    debug_assert!(data.len() >= OPTION_BYTES);

    let options = TerminalOptions {
        cols: forced_cols().unwrap_or_else(|| dimension(data[0], MAX_TERMINAL_COLS_BYTE)),
        rows: forced_rows().unwrap_or_else(|| dimension(data[1], MAX_TERMINAL_ROWS_BYTE)),
        max_scrollback: usize::from(data[2]) * SCROLLBACK_MULTIPLIER,
    };

    debug_assert!(options.cols > 0);
    debug_assert!(options.rows > 0);
    options
}

fn dimension(byte: u8, max_inclusive: u8) -> u16 {
    debug_assert!(max_inclusive > 0);

    let value = u16::from(byte % max_inclusive) + 1;

    debug_assert!(value > 0);
    debug_assert!(value <= u16::from(max_inclusive));
    value
}

fn install_effect_handlers(
    terminal: &mut Terminal<'static, 'static>,
) -> libghostty_vt::error::Result<()> {
    terminal
        .on_pty_write(|_terminal, data| {
            std::hint::black_box(data.len());
        })?
        .on_bell(|_terminal| {})?
        .on_enquiry(|_terminal| Some("libghostty-rs afl"))?
        .on_xtversion(|_terminal| Some("libghostty-rs-afl 0"))?
        .on_title_changed(|terminal| {
            if let Ok(title) = terminal.title() {
                std::hint::black_box(title.len());
            }
        })?;

    Ok(())
}

fn exercise_rendering(terminal: &Terminal<'static, 'static>) {
    let Ok(mut render_state) = RenderState::new() else {
        return;
    };
    let Ok(snapshot) = render_state.update(terminal) else {
        return;
    };

    let _dirty = snapshot.dirty();
    let _colors = snapshot.colors();
    let _cursor_visible = snapshot.cursor_visible();
    let _cursor_viewport = snapshot.cursor_viewport();

    let Ok(mut rows) = RowIterator::new() else {
        return;
    };
    let Ok(mut cells) = CellIterator::new() else {
        return;
    };
    let Ok(mut row_iter) = rows.update(&snapshot) else {
        return;
    };

    while let Some(row) = row_iter.next() {
        let _row_dirty = row.dirty();
        let Ok(mut cell_iter) = cells.update(row) else {
            continue;
        };

        while let Some(cell) = cell_iter.next() {
            let _style = cell.style();
            let _fg_color = cell.fg_color();
            let _bg_color = cell.bg_color();
            let _graphemes_len = cell.graphemes_len();
        }
    }
}
