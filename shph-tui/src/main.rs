use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use shph_config::Config;
use std::io::{self, Stdout};
use std::time::Duration;

struct AppState {
    config_path: std::path::PathBuf,
    config: Option<Config>,
    error: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = Config::default_config_path();
    let mut app = AppState {
        config_path: config_path.clone(),
        config: None,
        error: None,
    };
    match Config::load(&config_path) {
        Ok(cfg) => app.config = Some(cfg),
        Err(err) => app.error = Some(err.to_string()),
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut running = true;
    while running {
        terminal.draw(|frame| draw_ui(frame, &app))?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => running = false,
                    KeyCode::Char('r') => match Config::load(&app.config_path) {
                        Ok(cfg) => {
                            app.config = Some(cfg);
                            app.error = None;
                        }
                        Err(err) => app.error = Some(err.to_string()),
                    },
                    _ => {}
                }
            }
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}

fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.size());

    let header = Paragraph::new(Line::from(vec![
        Span::styled("SHPH TUI", Style::default().fg(Color::Cyan)),
        Span::raw("  |  "),
        Span::raw(format!("config: {}", app.config_path.display())),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Overview"));
    frame.render_widget(header, chunks[0]);

    let body = if let Some(cfg) = &app.config {
        render_config_view(cfg)
    } else {
        List::new(vec![ListItem::new(
            app.error.as_deref().map_or("No config loaded", |e| e),
        )])
        .block(Block::default().borders(Borders::ALL).title("Config Error"))
    };
    frame.render_widget(body, chunks[1]);

    let footer = Paragraph::new("q: quit  r: reload config")
        .block(Block::default().borders(Borders::ALL).title("Keys"));
    frame.render_widget(footer, chunks[2]);
}

fn render_config_view(cfg: &Config) -> List<'static> {
    let mut items = Vec::new();
    items.push(ListItem::new(format!("interface: {}", cfg.interface_name)));
    items.push(ListItem::new(format!(
        "local_endpoint: {}",
        cfg.local_endpoint
    )));
    items.push(ListItem::new(format!("peers: {}", cfg.peers.len())));
    if let Some(session) = &cfg.session {
        items.push(ListItem::new(format!("session.role: {:?}", session.role)));
        items.push(ListItem::new(format!(
            "session.bind: {}",
            session.bind.as_deref().unwrap_or("-")
        )));
        items.push(ListItem::new(format!(
            "session.peer: {}",
            session.peer.as_deref().unwrap_or("-")
        )));
        items.push(ListItem::new(format!(
            "session.timeout_secs: {}",
            session.timeout_secs.unwrap_or(5)
        )));
    } else {
        items.push(ListItem::new("session: none"));
    }
    if let Some(control) = &cfg.control_plane {
        items.push(ListItem::new(format!(
            "control_plane.routes: {}",
            control.route_cidrs.as_ref().map_or(0, |r| r.len())
        )));
        items.push(ListItem::new(format!(
            "control_plane.dns: {}",
            control.dns_servers.as_ref().map_or(0, |d| d.len())
        )));
        items.push(ListItem::new(format!(
            "control_plane.dry_run: {}",
            control.dry_run.unwrap_or(true)
        )));
    } else {
        items.push(ListItem::new("control_plane: none"));
    }
    List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Config Snapshot"),
    )
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
) -> Result<(), Box<dyn std::error::Error>> {
    disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}
