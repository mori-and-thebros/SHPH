use clap::Parser;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use shph_config::{Config, SessionRole};
use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Parser)]
#[command(
    name = "shph-tui",
    about = "SHPH terminal dashboard for configuration and operator status",
    after_help = "Keys: 1-4 views, Tab next view, r reload, ? help, q quit"
)]
struct Args {
    /// Use a specific configuration file
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Overview,
    Peers,
    Session,
    ControlPlane,
}

impl View {
    const ALL: [Self; 4] = [
        Self::Overview,
        Self::Peers,
        Self::Session,
        Self::ControlPlane,
    ];

    fn number(self) -> char {
        match self {
            Self::Overview => '1',
            Self::Peers => '2',
            Self::Session => '3',
            Self::ControlPlane => '4',
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Peers => "Peers",
            Self::Session => "Session",
            Self::ControlPlane => "Control plane",
        }
    }

    fn next(self) -> Self {
        let index = Self::ALL.iter().position(|view| *view == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }
}

struct AppState {
    config_path: PathBuf,
    config: Option<Config>,
    error: Option<String>,
    view: View,
    peer_index: usize,
    show_help: bool,
    last_loaded: Option<SystemTime>,
}

impl AppState {
    fn new(config_path: PathBuf) -> Self {
        let mut app = Self {
            config_path,
            config: None,
            error: None,
            view: View::Overview,
            peer_index: 0,
            show_help: false,
            last_loaded: None,
        };
        app.reload();
        app
    }

    fn reload(&mut self) {
        match Config::load(&self.config_path) {
            Ok(config) => {
                self.peer_index = self.peer_index.min(config.peers.len().saturating_sub(1));
                self.config = Some(config);
                self.error = None;
                self.last_loaded = Some(SystemTime::now());
            }
            Err(error) => {
                self.config = None;
                self.error = Some(error.to_string());
                self.last_loaded = Some(SystemTime::now());
            }
        }
    }

    fn handle_key(&mut self, key: KeyCode) -> bool {
        if self.show_help {
            if matches!(key, KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')) {
                self.show_help = false;
            }
            return true;
        }

        match key {
            KeyCode::Char('q') | KeyCode::Esc => false,
            KeyCode::Char('r') => {
                self.reload();
                true
            }
            KeyCode::Char('?') => {
                self.show_help = true;
                true
            }
            KeyCode::Char('1') => {
                self.view = View::Overview;
                true
            }
            KeyCode::Char('2') => {
                self.view = View::Peers;
                true
            }
            KeyCode::Char('3') => {
                self.view = View::Session;
                true
            }
            KeyCode::Char('4') => {
                self.view = View::ControlPlane;
                true
            }
            KeyCode::Tab => {
                self.view = self.view.next();
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(config) = &self.config {
                    if !config.peers.is_empty() {
                        self.peer_index = (self.peer_index + 1).min(config.peers.len() - 1);
                    }
                }
                true
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.peer_index = self.peer_index.saturating_sub(1);
                true
            }
            KeyCode::Home => {
                self.peer_index = 0;
                true
            }
            KeyCode::End => {
                if let Some(config) = &self.config {
                    self.peer_index = config.peers.len().saturating_sub(1);
                }
                true
            }
            _ => true,
        }
    }
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    restored: bool,
}

impl TerminalSession {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        enable_raw_mode()?;
        if let Err(error) = crossterm::execute!(
            terminal.backend_mut(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::event::EnableMouseCapture
        ) {
            let _ = disable_raw_mode();
            return Err(Box::new(error));
        }
        Ok(Self {
            terminal,
            restored: false,
        })
    }

    fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.restored {
            restore_terminal(&mut self.terminal)?;
            self.restored = true;
        }
        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config_path = args.config.unwrap_or_else(Config::default_config_path);
    let mut app = AppState::new(config_path);

    let mut terminal = TerminalSession::new()?;
    let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_app(terminal.terminal_mut(), &mut app)
    }));
    let restore_result = terminal.restore();

    match run_result {
        Ok(Ok(())) => restore_result,
        Ok(Err(error)) => {
            if let Err(restore_error) = restore_result {
                eprintln!("warning: failed to restore terminal: {restore_error}");
            }
            Err(error)
        }
        Err(payload) => {
            if let Err(restore_error) = restore_result {
                eprintln!("warning: failed to restore terminal after panic: {restore_error}");
            }
            std::panic::resume_unwind(payload);
        }
    }
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut AppState,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|frame| draw_ui(frame, app))?;
        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => {
                    if !app.handle_key(key.code) {
                        break;
                    }
                }
                Event::Resize(_, _) => terminal.clear()?,
                _ => {}
            }
        }
    }
    Ok(())
}

fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    render_header(frame, chunks[0], app);
    if app.error.is_some() {
        render_error(frame, chunks[1], app);
    } else if app.config.is_some() {
        match app.view {
            View::Overview => render_overview(frame, chunks[1], app),
            View::Peers => render_peers(frame, chunks[1], app),
            View::Session => render_session(frame, chunks[1], app),
            View::ControlPlane => render_control_plane(frame, chunks[1], app),
        }
    } else {
        render_empty(
            frame,
            chunks[1],
            "No configuration loaded. Press r to retry.",
        );
    }
    render_footer(frame, chunks[2], app);

    if app.show_help {
        render_help(frame);
    }
}

fn render_header(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let state = if app.error.is_some() {
        ("ERROR", Color::Red)
    } else if app.config.is_some() {
        ("READY", Color::Green)
    } else {
        ("EMPTY", Color::Yellow)
    };
    let tabs = View::ALL
        .iter()
        .map(|view| {
            if *view == app.view {
                Span::styled(
                    format!(" {} {} ", view.number(), view.title()),
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    format!(" {} {} ", view.number(), view.title()),
                    Style::default().fg(Color::DarkGray),
                )
            }
        })
        .collect::<Vec<_>>();

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                " SHPH ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(state.0, Style::default().fg(state.1)),
            Span::raw("  "),
            Span::raw(app.config_path.display().to_string()),
        ]),
        Line::from(tabs),
    ];
    if let Some(loaded) = app.last_loaded {
        lines.push(Line::from(Span::styled(
            format!(" Last refresh: {}", elapsed_since(loaded)),
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("SHPH dashboard"),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_overview(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let config = app.config.as_ref().expect("overview requires config");
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);

    let summary = vec![
        ListItem::new(format!("Interface       {}", config.interface_name)),
        ListItem::new(format!("Local endpoint  {}", config.local_endpoint)),
        ListItem::new(format!("Configured peers {}", config.peers.len())),
        ListItem::new(format!("Session          {}", session_summary(config))),
        ListItem::new(format!(
            "Control plane    {}",
            if config.control_plane.is_some() {
                "configured"
            } else {
                "not configured"
            }
        )),
        ListItem::new(format!(
            "Native TUN       {}",
            if native_tun_requested() {
                "requested"
            } else {
                "disabled"
            }
        )),
    ];
    frame.render_widget(
        List::new(summary).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Configuration"),
        ),
        columns[0],
    );

    let checks = vec![
        readiness_item("Config file", true, "loaded successfully"),
        readiness_item(
            "Identity",
            keystore_path_for(&app.config_path).is_file(),
            "keystore file present",
        ),
        readiness_item(
            "Native packet I/O",
            native_tun_requested(),
            if native_tun_requested() {
                "SHPH_TUN_NATIVE=1"
            } else {
                "set SHPH_TUN_NATIVE=1 when native TUN is available"
            },
        ),
        readiness_item(
            "Control-plane state",
            control_plane_state_path(&app.config_path).is_file(),
            if control_plane_state_path(&app.config_path).is_file() {
                "persisted state found"
            } else {
                "no applied state recorded"
            },
        ),
    ];
    frame.render_widget(
        List::new(checks).block(Block::default().borders(Borders::ALL).title("Readiness")),
        columns[1],
    );
}

fn render_peers(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let config = app.config.as_ref().expect("peers view requires config");
    if config.peers.is_empty() {
        render_empty(
            frame,
            area,
            "No peers configured.\nUse `shph add-peer ...` from the CLI.",
        );
        return;
    }

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);
    let items = config
        .peers
        .iter()
        .map(|peer| ListItem::new(Line::from(vec![Span::raw(peer.alias.clone())])))
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    state.select(Some(app.peer_index.min(config.peers.len() - 1)));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Peers"))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ "),
        columns[0],
        &mut state,
    );

    let peer = &config.peers[app.peer_index.min(config.peers.len() - 1)];
    let details = vec![
        Line::from(Span::styled(
            peer.alias.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("Endpoint: {}", peer.endpoint)),
        Line::from(format!("Public key: {}", shorten_key(&peer.pubkey))),
        Line::from(format!(
            "Signing key: {}",
            if peer.sign_pubkey.is_some() {
                "configured"
            } else {
                "missing"
            }
        )),
        Line::from(""),
        Line::from(Span::styled(
            "j/k or ↑/↓ select peer",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(Text::from(details))
            .block(Block::default().borders(Borders::ALL).title("Peer details"))
            .wrap(Wrap { trim: true }),
        columns[1],
    );
}

fn render_session(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let config = app.config.as_ref().expect("session view requires config");
    let Some(session) = &config.session else {
        render_empty(
            frame,
            area,
            "No persistent session is configured.\nUse `shph listen` or `shph connect` for one-shot operations.",
        );
        return;
    };

    let mut lines = vec![
        Line::from(Span::styled(
            "Configured session",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("Role: {:?}", session.role)),
        Line::from(format!(
            "Bind: {}",
            session.bind.as_deref().unwrap_or("default")
        )),
        Line::from(format!(
            "Peer: {}",
            session.peer.as_deref().unwrap_or("not configured")
        )),
        Line::from(format!(
            "Timeout: {} seconds",
            session.timeout_secs.unwrap_or(5)
        )),
        Line::from(format!(
            "Handshake profile: {}",
            session
                .handshake_profile
                .map(|profile| profile.as_str())
                .unwrap_or("secure-default")
        )),
        Line::from(format!(
            "Reconnect: {}",
            session
                .reconnect
                .as_ref()
                .and_then(|reconnect| reconnect.enabled)
                .map(|enabled| enabled.to_string())
                .unwrap_or_else(|| "disabled".into())
        )),
        Line::from(""),
        Line::from(Span::styled(
            "The dashboard is read-only. Start or stop sessions with the CLI.",
            Style::default().fg(Color::Yellow),
        )),
    ];
    if let SessionRole::Connect = session.role {
        lines.push(Line::from(Span::styled(
            "Tip: run `shph doctor` before connecting.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(Block::default().borders(Borders::ALL).title("Session"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_control_plane(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let config = app
        .config
        .as_ref()
        .expect("control-plane view requires config");
    let Some(control) = &config.control_plane else {
        render_empty(
            frame,
            area,
            "No route/DNS control-plane configuration is present.",
        );
        return;
    };

    let routes = control.route_cidrs.as_deref().unwrap_or(&[]);
    let dns = control.dns_servers.as_deref().unwrap_or(&[]);
    let mut lines = vec![
        Line::from(Span::styled(
            "Configured mutations",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "Routes: {} ({})",
            routes.len(),
            if control.apply_routes.unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
        )),
    ];
    lines.extend(
        routes
            .iter()
            .map(|route| Line::from(format!("  • {route}"))),
    );
    lines.push(Line::from(format!(
        "DNS: {} ({})",
        dns.len(),
        if control.apply_dns.unwrap_or(false) {
            "enabled"
        } else {
            "disabled"
        }
    )));
    lines.extend(dns.iter().map(|server| Line::from(format!("  • {server}"))));
    lines.push(Line::from(format!(
        "Dry run: {}",
        control.dry_run.unwrap_or(true)
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Apply/reconcile/undo remain explicit CLI actions.",
        Style::default().fg(Color::Yellow),
    )));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Control plane"),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_error(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let message = app
        .error
        .as_deref()
        .unwrap_or("unknown configuration error");
    let text = Text::from(vec![
        Line::from(Span::styled(
            "Configuration could not be loaded",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(message),
        Line::from(""),
        Line::from(Span::styled(
            "Press r to retry after fixing the file, or q to quit.",
            Style::default().fg(Color::Yellow),
        )),
    ]);
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Error"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_empty(frame: &mut ratatui::Frame<'_>, area: Rect, message: &str) {
    frame.render_widget(
        Paragraph::new(message)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("No data"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_footer(frame: &mut ratatui::Frame<'_>, area: Rect, app: &AppState) {
    let footer = if app.show_help {
        "Esc/? close help"
    } else {
        "1-4 view  Tab next  r reload  ? help  q quit"
    };
    frame.render_widget(
        Paragraph::new(footer)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("Keys")),
        area,
    );
}

fn render_help(frame: &mut ratatui::Frame<'_>) {
    let area = centered_rect(72, 62, frame.area());
    let text = Text::from(vec![
        Line::from(Span::styled(
            "SHPH TUI help",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("1  Overview       Configuration and readiness summary"),
        Line::from("2  Peers          Browse configured peers"),
        Line::from("3  Session        Review persistent session settings"),
        Line::from("4  Control plane  Review routes and DNS settings"),
        Line::from("Tab              Move to the next view"),
        Line::from("r                Reload the configuration"),
        Line::from("j/k, ↑/↓         Select a peer"),
        Line::from("q, Esc           Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "The TUI is intentionally read-only; use the CLI for privileged actions.",
            Style::default().fg(Color::Yellow),
        )),
    ]);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Help"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn readiness_item(name: &str, ready: bool, detail: &str) -> ListItem<'static> {
    let (marker, color) = if ready {
        ("PASS", Color::Green)
    } else {
        ("INFO", Color::Yellow)
    };
    ListItem::new(Line::from(vec![
        Span::styled(format!("[{marker}] "), Style::default().fg(color)),
        Span::raw(format!("{name}: {detail}")),
    ]))
}

fn session_summary(config: &Config) -> String {
    let Some(session) = &config.session else {
        return "not configured".into();
    };
    match session.role {
        SessionRole::Listen => format!("listen {}", session.bind.as_deref().unwrap_or("default")),
        SessionRole::Connect => format!("connect {}", session.peer.as_deref().unwrap_or("unset")),
    }
}

fn native_tun_requested() -> bool {
    std::env::var("SHPH_TUN_NATIVE").ok().as_deref() == Some("1")
}

fn keystore_path_for(config_path: &Path) -> PathBuf {
    let mut path = config_path.to_path_buf();
    path.set_file_name("keystore.json");
    path
}

fn control_plane_state_path(config_path: &Path) -> PathBuf {
    let mut path = config_path.to_path_buf();
    path.set_extension("control-plane.json");
    path
}

fn elapsed_since(time: SystemTime) -> String {
    match SystemTime::now().duration_since(time) {
        Ok(duration) if duration.as_secs() == 0 => "just now".into(),
        Ok(duration) => format!("{}s ago", duration.as_secs()),
        Err(_) => "clock adjusted".into(),
    }
}

fn shorten_key(value: &str) -> String {
    const EDGE: usize = 10;
    if value.len() <= EDGE * 2 + 3 {
        return value.to_string();
    }
    format!("{}...{}", &value[..EDGE], &value[value.len() - EDGE..])
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
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
