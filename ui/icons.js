'use strict';
// Device icons. Every icon is a list of SVG shapes drawn on a 24x24 grid with
// a 1.7px stroke and no fill, so they inherit the surrounding text colour and
// work in both themes. They are built as DOM nodes (never as HTML strings).
//
// The server stores only the icon *name* (validated against a fixed list in
// tracking.rs); an unknown name simply falls back to the generic icon, so
// adding an icon here never breaks older data.

const ICON_SHAPES = {
  laptop: [['rect', { x: 4, y: 5, width: 16, height: 11, rx: 1.5 }], ['path', { d: 'M2 19h20' }]],
  desktop: [['rect', { x: 3, y: 4, width: 18, height: 12, rx: 1.5 }], ['path', { d: 'M9 20h6M12 16v4' }]],
  server: [['rect', { x: 3, y: 3, width: 18, height: 7, rx: 1.5 }], ['rect', { x: 3, y: 14, width: 18, height: 7, rx: 1.5 }], ['path', { d: 'M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6' }]],
  phone: [['rect', { x: 7, y: 2, width: 10, height: 20, rx: 2 }], ['path', { d: 'M11 18.5h2' }]],
  tablet: [['rect', { x: 4, y: 3, width: 16, height: 18, rx: 2 }], ['path', { d: 'M11 18h2' }]],
  printer: [['path', { d: 'M7 9V3h10v6' }], ['rect', { x: 3, y: 9, width: 18, height: 8, rx: 1.5 }], ['rect', { x: 7, y: 14, width: 10, height: 7 }]],
  scanner: [['rect', { x: 3, y: 12, width: 18, height: 7, rx: 1.5 }], ['path', { d: 'M5 12l3-6h8l3 6M7 15.5h.01' }]],
  router: [['rect', { x: 3, y: 13, width: 18, height: 7, rx: 1.5 }], ['path', { d: 'M7 16.5h.01M11 16.5h.01M7 13V8M17 13V8M12 13V5' }]],
  switch: [['rect', { x: 2, y: 8, width: 20, height: 8, rx: 1.5 }], ['path', { d: 'M6 12h.01M10 12h.01M14 12h.01M18 12h.01' }]],
  access_point: [['path', { d: 'M4 10a11 11 0 0 1 16 0M7.5 13.5a6 6 0 0 1 9 0' }], ['circle', { cx: 12, cy: 17, r: 1.2 }], ['path', { d: 'M12 18.5V21' }]],
  firewall: [['rect', { x: 3, y: 4, width: 18, height: 16, rx: 1.5 }], ['path', { d: 'M3 9.3h18M3 14.7h18M9 4v5.3M15 9.3v5.4M9 14.7V20' }]],
  camera: [['rect', { x: 2, y: 7, width: 14, height: 10, rx: 2 }], ['path', { d: 'M16 10.5l6-3.5v10l-6-3.5' }]],
  tv: [['rect', { x: 2, y: 4, width: 20, height: 13, rx: 1.5 }], ['path', { d: 'M8 21h8M12 17v4' }]],
  media_player: [['rect', { x: 3, y: 8, width: 18, height: 8, rx: 2.5 }], ['path', { d: 'M15 12h3M7 12h.01' }]],
  speaker: [['rect', { x: 6, y: 2, width: 12, height: 20, rx: 3 }], ['circle', { cx: 12, cy: 15, r: 3 }], ['path', { d: 'M12 7h.01' }]],
  smart_plug: [['rect', { x: 5, y: 5, width: 14, height: 14, rx: 4 }], ['path', { d: 'M10 9.5v2M14 9.5v2M10 15h4' }]],
  iot: [['rect', { x: 7, y: 7, width: 10, height: 10, rx: 1.5 }], ['path', { d: 'M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4' }]],
  sensor: [['circle', { cx: 12, cy: 12, r: 2.2 }], ['path', { d: 'M7.8 7.8a6 6 0 0 0 0 8.4M16.2 7.8a6 6 0 0 1 0 8.4M4.9 4.9a10 10 0 0 0 0 14.2M19.1 4.9a10 10 0 0 1 0 14.2' }]],
  thermostat: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 12l3-4M8 16.5h8' }]],
  nas: [['rect', { x: 4, y: 3, width: 16, height: 18, rx: 2 }], ['path', { d: 'M8 8h8M8 12h8M8 16h3M16 16h.01' }]],
  game_console: [['rect', { x: 2, y: 8, width: 20, height: 9, rx: 4.5 }], ['path', { d: 'M7 10.5v4M5 12.5h4M15.5 11h.01M18 13.5h.01' }]],
  watch: [['rect', { x: 7, y: 6, width: 10, height: 12, rx: 3 }], ['path', { d: 'M9 6l1-4h4l1 4M9 18l1 4h4l1-4M12 10v2.5l1.5 1' }]],
  raspberry_pi: [['rect', { x: 3, y: 6, width: 18, height: 12, rx: 1.5 }], ['path', { d: 'M6 9h4v3H6zM13 9h2M13 12h2M17 9h.01M17 12h.01M6 15h.01M9 15h.01M12 15h.01' }]],
  virtual_machine: [['path', { d: 'M12 3l8 4.5v9L12 21l-8-4.5v-9z' }], ['path', { d: 'M12 12l8-4.5M12 12v9M12 12L4 7.5' }]],
  voip_phone: [['path', { d: 'M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2' }]],
  ups: [['rect', { x: 3, y: 6, width: 18, height: 12, rx: 2 }], ['path', { d: 'M12.5 8.5L9.5 12.5H14l-3 4' }]],
  plc: [['rect', { x: 3, y: 3, width: 18, height: 18, rx: 1.5 }], ['path', { d: 'M7 7h4M7 11h4M7 15h4M15 7h2M15 11h2M15 15h2' }]],
  hmi: [['rect', { x: 3, y: 4, width: 18, height: 12, rx: 1.5 }], ['path', { d: 'M7 12l2.5-3 2.5 2 3-4M8 20h8M12 16v4' }]],
  rtu: [['rect', { x: 4, y: 11, width: 16, height: 9, rx: 1.5 }], ['path', { d: 'M8 15.5h.01M12 15.5h.01M12 11V4M9 6.5a4 4 0 0 1 6 0' }]],
  scada: [['rect', { x: 2, y: 4, width: 20, height: 13, rx: 1.5 }], ['path', { d: 'M5 13l3-4 3 2 3-5 3 4M8 21h8M12 17v4' }]],
  gateway: [['path', { d: 'M4 8h13M14 5l3 3-3 3M20 16H7M10 13l-3 3 3 3' }]],
  drive: [['circle', { cx: 12, cy: 12, r: 8 }], ['path', { d: 'M8.5 15.5v-7l3.5 4 3.5-4v7' }]],
  robot: [['path', { d: 'M4 21h8M8 21v-6l5-6M13 9l4-4M17 5l3 1-1 3' }], ['circle', { cx: 13, cy: 9, r: 1.3 }]],
  building: [['rect', { x: 5, y: 3, width: 14, height: 18, rx: 1 }], ['path', { d: 'M9 7h.01M12 7h.01M15 7h.01M9 11h.01M12 11h.01M15 11h.01M9 15h.01M15 15h.01M11 21v-4h2v4' }]],
  apple: [['path', { d: 'M12 8.5c-1.5-1.2-4-1-5.2 1-1.4 2.3-.5 6.2 1.4 8.4 1 1.2 2.2 1.6 3.8.9 1.6.7 2.8.3 3.8-.9 1.9-2.2 2.8-6.1 1.4-8.4-1.2-2-3.7-2.2-5.2-1z' }], ['path', { d: 'M12 8.5c0-2 1-3.6 3-4.5' }]],
  windows: [['path', { d: 'M3 5.5l7.5-1v7H3zM12 4.3L21 3v8.5h-9zM3 13h7.5v7L3 18.8zM12 13h9v8l-9-1.3z' }]],
  linux: [['rect', { x: 3, y: 4, width: 18, height: 16, rx: 2 }], ['path', { d: 'M7 9l3 3-3 3M12 16h5' }]],
  android: [['path', { d: 'M5 16a7 7 0 0 1 14 0zM8 6l1.5 2.2M16 6l-1.5 2.2M9 12h.01M15 12h.01M8 16v4M16 16v4' }]],
  thin_client: [['rect', { x: 4, y: 3, width: 16, height: 12, rx: 1.5 }], ['rect', { x: 8, y: 18, width: 8, height: 3, rx: 0.8 }], ['path', { d: 'M12 15v3' }]],
  pos: [['rect', { x: 5, y: 2, width: 14, height: 20, rx: 2 }], ['rect', { x: 8, y: 5, width: 8, height: 5 }], ['path', { d: 'M8 14h.01M12 14h.01M16 14h.01M8 17.5h.01M12 17.5h.01M16 17.5h.01' }]],
  kiosk: [['rect', { x: 6, y: 2, width: 12, height: 13, rx: 1.5 }], ['path', { d: 'M9 15v6h6v-6M4 21h16' }]],
  hypervisor: [['rect', { x: 3, y: 3, width: 18, height: 6, rx: 1.5 }], ['rect', { x: 3, y: 11, width: 8, height: 10, rx: 1.5 }], ['rect', { x: 13, y: 11, width: 8, height: 10, rx: 1.5 }]],
  database: [['ellipse', { cx: 12, cy: 6, rx: 8, ry: 3 }], ['path', { d: 'M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6' }]],
  storage_array: [['rect', { x: 3, y: 3, width: 18, height: 5, rx: 1 }], ['rect', { x: 3, y: 10, width: 18, height: 5, rx: 1 }], ['rect', { x: 3, y: 17, width: 18, height: 4, rx: 1 }], ['path', { d: 'M6 5.5h.01M6 12.5h.01M6 19h.01M10 5.5h8M10 12.5h8M10 19h8' }]],
  kvm: [['rect', { x: 3, y: 4, width: 18, height: 10, rx: 1.5 }], ['rect', { x: 6, y: 17, width: 12, height: 4, rx: 1 }], ['path', { d: 'M12 14v3' }]],
  pdu: [['rect', { x: 2, y: 8, width: 20, height: 8, rx: 1.5 }], ['path', { d: 'M5 11v2M7 11v2M11 11v2M13 11v2M17 11v2M19 11v2' }]],
  load_balancer: [['circle', { cx: 12, cy: 5, r: 2 }], ['path', { d: 'M12 7v3M12 10L5 15M12 10l7 5M12 10v5' }], ['rect', { x: 3, y: 15, width: 4, height: 5, rx: 1 }], ['rect', { x: 10, y: 15, width: 4, height: 5, rx: 1 }], ['rect', { x: 17, y: 15, width: 4, height: 5, rx: 1 }]],
  vpn: [['path', { d: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z' }], ['rect', { x: 9, y: 11, width: 6, height: 5, rx: 1 }], ['path', { d: 'M10 11V9.5a2 2 0 0 1 4 0V11' }]],
  security_appliance: [['path', { d: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z' }], ['path', { d: 'M9 12l2 2 4-4' }]],
  modem: [['rect', { x: 3, y: 12, width: 18, height: 7, rx: 1.5 }], ['path', { d: 'M7 15.5h.01M11 15.5h.01M8 12V6M16 12V6' }]],
  mesh_node: [['circle', { cx: 12, cy: 12, r: 7 }], ['circle', { cx: 12, cy: 12, r: 2 }], ['path', { d: 'M12 3v2M12 19v2M3 12h2M19 12h2' }]],
  cloud: [['path', { d: 'M7 18a4 4 0 0 1-.5-8 5.5 5.5 0 0 1 10.6-1A4.5 4.5 0 0 1 17 18z' }]],
  projector: [['rect', { x: 3, y: 8, width: 18, height: 9, rx: 2 }], ['circle', { cx: 15, cy: 12.5, r: 2.5 }], ['path', { d: 'M6 11.5h3M6 20v-3M18 20v-3' }]],
  conference: [['circle', { cx: 12, cy: 12, r: 9 }], ['circle', { cx: 12, cy: 12, r: 3 }], ['path', { d: 'M12 3v3M12 18v3M3 12h3M18 12h3' }]],
  streaming_stick: [['rect', { x: 3, y: 9, width: 14, height: 6, rx: 2 }], ['path', { d: 'M17 12h4M7 12h.01' }]],
  smart_light: [['path', { d: 'M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9c.5.4.8 1 .8 1.6V16h5.4v-.5c0-.6.3-1.2.8-1.6A6 6 0 0 0 12 3z' }]],
  smart_lock: [['rect', { x: 5, y: 10, width: 14, height: 11, rx: 2 }], ['path', { d: 'M8 10V7a4 4 0 0 1 8 0v3M12 14.5v3' }]],
  doorbell: [['rect', { x: 7, y: 2, width: 10, height: 20, rx: 3 }], ['circle', { cx: 12, cy: 8, r: 2 }], ['circle', { cx: 12, cy: 16, r: 2 }]],
  badge_reader: [['rect', { x: 6, y: 2, width: 12, height: 20, rx: 2 }], ['path', { d: 'M9 8.5a4.5 4.5 0 0 1 6 0M10.5 11a2.5 2.5 0 0 1 3 0M12 14h.01M9 19h6' }]],
  alarm_panel: [['rect', { x: 4, y: 3, width: 16, height: 18, rx: 2 }], ['path', { d: 'M8 7h8v3H8zM8 14h.01M12 14h.01M16 14h.01M8 17.5h.01M12 17.5h.01M16 17.5h.01' }]],
  smoke_detector: [['circle', { cx: 12, cy: 12, r: 9 }], ['circle', { cx: 12, cy: 12, r: 2 }], ['path', { d: 'M7 12h.01M9 8h.01M12 6.5h.01M15 8h.01M17 12h.01' }]],
  hvac: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 12c0-3 .8-5 2.5-5 1.7 0 1.7 1.7 0 3.5M12 12c3 0 5 .8 5 2.5 0 1.7-1.7 1.7-3.5 0M12 12c0 3-.8 5-2.5 5-1.7 0-1.7-1.7 0-3.5M12 12c-3 0-5-.8-5-2.5 0-1.7 1.7-1.7 3.5 0' }]],
  smart_hub: [['rect', { x: 4, y: 4, width: 16, height: 16, rx: 5 }], ['circle', { cx: 12, cy: 12, r: 2.5 }], ['path', { d: 'M8.5 8.5a5 5 0 0 1 7 0' }]],
  vacuum: [['circle', { cx: 12, cy: 12, r: 9 }], ['circle', { cx: 12, cy: 12, r: 3.5 }], ['path', { d: 'M17.5 6.5h.01' }]],
  appliance: [['rect', { x: 5, y: 2, width: 14, height: 20, rx: 2 }], ['path', { d: 'M5 8h14M8 5h.01M11 5h.01' }], ['circle', { cx: 12, cy: 15, r: 3.5 }]],
  printer_3d: [['path', { d: 'M4 3h16M4 21h16M6 3v18M18 3v18' }], ['path', { d: 'M9 9h6v3H9zM12 12v3' }]],
  medical: [['rect', { x: 3, y: 3, width: 18, height: 18, rx: 3 }], ['path', { d: 'M12 7v10M7 12h10' }]],
  ev_charger: [['rect', { x: 5, y: 3, width: 9, height: 18, rx: 1.5 }], ['path', { d: 'M14 9h2a2 2 0 0 1 2 2v5a1.5 1.5 0 0 0 3 0V8l-2-2M9.5 8l-2 4h3l-2 4' }]],
  inverter: [['rect', { x: 3, y: 4, width: 18, height: 16, rx: 2 }], ['path', { d: 'M7 9h3M14 9h3M7 15c1.3-4 2.7-4 4 0s2.7 4 4 0' }]],
  vehicle: [['path', { d: 'M4 15l2-6h12l2 6v4h-3v-2H7v2H4z' }], ['path', { d: 'M4 15h16M7.5 12.5h.01M16.5 12.5h.01' }]],
  safety_controller: [['rect', { x: 3, y: 3, width: 18, height: 18, rx: 1.5 }], ['path', { d: 'M12 7l4 1.5v3.2c0 2.4-1.7 4-4 4.8-2.3-.8-4-2.4-4-4.8V8.5z' }]],
  protection_relay: [['rect', { x: 3, y: 6, width: 18, height: 12, rx: 1.5 }], ['path', { d: 'M7 12h3l1.5-3 2 6L15 12h2' }]],
  power_meter: [['path', { d: 'M4 16a8 8 0 1 1 16 0' }], ['path', { d: 'M12 16l4-5M4 16h16M8 20h8' }]],
  remote_io: [['rect', { x: 3, y: 7, width: 18, height: 10, rx: 1.5 }], ['path', { d: 'M7 11h2M11 11h2M15 11h2M7 14h2M11 14h2M15 14h2' }]],
  industrial_pc: [['rect', { x: 4, y: 3, width: 16, height: 18, rx: 1.5 }], ['rect', { x: 7, y: 6, width: 10, height: 7 }], ['path', { d: 'M8 17h.01M12 17h.01M16 17h.01' }]],
  cnc: [['rect', { x: 3, y: 3, width: 18, height: 18, rx: 1.5 }], ['path', { d: 'M3 8h18M8 8v13M12 14h6M15 11v6' }]],
  rfid: [['circle', { cx: 8, cy: 16, r: 2 }], ['path', { d: 'M8 10a6 6 0 0 1 6 6M8 5a11 11 0 0 1 11 11' }]],
  barcode_scanner: [['rect', { x: 2, y: 3, width: 20, height: 18, rx: 2 }], ['path', { d: 'M6 8v8M8.5 8v8M11 8v8M15 8v8M18 8v8' }]],
  pump: [['circle', { cx: 10, cy: 14, r: 5 }], ['path', { d: 'M10 9V5h6v4M15 14h6' }]],
  valve: [['path', { d: 'M3 12h4M17 12h4' }], ['path', { d: 'M7 7l10 10V7L7 17z' }], ['path', { d: 'M12 12V5M9 5h6' }]],
  motor: [['rect', { x: 4, y: 8, width: 12, height: 8, rx: 2 }], ['path', { d: 'M16 10h3v4h-3M4 12H2M8 8V6h4v2' }]],
  // added in 0.1.4: robots, appliances, smart home, energy, office/IT extras
  robot_mower: [['path', { d: 'M4 16c0-3.5 3-7 8-7s8 3.5 8 7z' }], ['circle', { cx: 7.5, cy: 18, r: 2 }], ['circle', { cx: 16.5, cy: 18, r: 2 }], ['path', { d: 'M12 9V5.5M10 5.5h4' }]],
  drone: [['rect', { x: 10, y: 10, width: 4, height: 4, rx: 1 }], ['circle', { cx: 5, cy: 6, r: 2.2 }], ['circle', { cx: 19, cy: 6, r: 2.2 }], ['circle', { cx: 5, cy: 18, r: 2.2 }], ['circle', { cx: 19, cy: 18, r: 2.2 }], ['path', { d: 'M6.6 7.6L10 11M17.4 7.6L14 11M6.6 16.4L10 13M17.4 16.4L14 13' }]],
  irrigation: [['path', { d: 'M12 21v-7M9 14h6' }], ['path', { d: 'M7 9.5a7 7 0 0 1 10 0M9.5 12a3.6 3.6 0 0 1 5 0' }], ['path', { d: 'M5 5.5h.01M19 5.5h.01M12 4.5h.01M8 4h.01M16 4h.01' }]],
  fridge: [['rect', { x: 6, y: 2, width: 12, height: 20, rx: 2 }], ['path', { d: 'M6 10h12M9 6v2M9 13v3' }]],
  washing_machine: [['rect', { x: 4, y: 2, width: 16, height: 20, rx: 2 }], ['circle', { cx: 12, cy: 14, r: 5 }], ['path', { d: 'M8 6h.01M11 6h.01M15 6h2M9.5 14a2.5 2.5 0 0 1 5 0' }]],
  dishwasher: [['rect', { x: 4, y: 3, width: 16, height: 18, rx: 2 }], ['path', { d: 'M4 8h16M9.5 5.5h5M8 12v6M12 12v6M16 12v6' }]],
  oven: [['rect', { x: 3, y: 4, width: 18, height: 16, rx: 2 }], ['path', { d: 'M3 9h18M7 6.5h.01M11 6.5h.01M15 6.5h.01' }], ['rect', { x: 6, y: 11.5, width: 12, height: 6, rx: 1 }]],
  coffee_machine: [['path', { d: 'M6 9h10v5a4 4 0 0 1-4 4h-2a4 4 0 0 1-4-4z' }], ['path', { d: 'M16 10h2a2 2 0 0 1 0 4h-2M5 21h12M9 3c-1 1 1 2 0 3M13 3c-1 1 1 2 0 3' }]],
  air_purifier: [['rect', { x: 6, y: 3, width: 12, height: 18, rx: 3 }], ['path', { d: 'M9 8h6M9 11h6M9 14h6M12 18h.01' }]],
  air_conditioner: [['rect', { x: 2, y: 5, width: 20, height: 8, rx: 2 }], ['path', { d: 'M5 11h14M6 16.5c1 1 1 2 0 3M12 16.5c1 1 1 2 0 3M18 16.5c1 1 1 2 0 3' }]],
  heat_pump: [['rect', { x: 3, y: 5, width: 18, height: 15, rx: 2 }], ['circle', { cx: 12, cy: 12.5, r: 5 }], ['path', { d: 'M12 8v9M7.5 12.5h9' }]],
  water_heater: [['rect', { x: 6, y: 2, width: 12, height: 20, rx: 3 }], ['path', { d: 'M9 6h6M12 19c-2 0-3-1.4-3-3 0-2 3-3 3-6 3 2 3 5 3 6 0 1.6-1 3-3 3z' }]],
  smart_meter: [['circle', { cx: 12, cy: 12, r: 9 }], ['rect', { x: 8, y: 8, width: 8, height: 4, rx: 0.8 }], ['path', { d: 'M9 16h6' }]],
  battery_storage: [['rect', { x: 3, y: 7, width: 16, height: 11, rx: 2 }], ['path', { d: 'M19 10h2v5h-2M11 9.5l-2 3h4l-2 3' }]],
  soundbar: [['rect', { x: 2, y: 9, width: 20, height: 6, rx: 3 }], ['path', { d: 'M6 12h.01M10 12h.01M14 12h.01M18 12h.01M5 15v2M19 15v2' }]],
  av_receiver: [['rect', { x: 2, y: 7, width: 20, height: 10, rx: 1.5 }], ['circle', { cx: 7, cy: 12, r: 2 }], ['path', { d: 'M12 10h7M12 14h7' }]],
  smart_display: [['rect', { x: 3, y: 4, width: 18, height: 12, rx: 2 }], ['path', { d: 'M9 20h6M12 16v4M8 10h8' }]],
  vr_headset: [['rect', { x: 3, y: 7, width: 18, height: 9, rx: 3 }], ['path', { d: 'M10 16c0-2 4-2 4 0M3 11H1M21 11h2' }]],
  e_reader: [['rect', { x: 5, y: 2, width: 14, height: 20, rx: 2 }], ['path', { d: 'M8 7h8M8 10h8M8 13h5M12 19h.01' }]],
  baby_monitor: [['rect', { x: 5, y: 7, width: 14, height: 14, rx: 2.5 }], ['path', { d: 'M12 7V3M9.5 3h5' }], ['circle', { cx: 12, cy: 14, r: 3 }]],
  pet_feeder: [['path', { d: 'M4 12h16l-2 8H6z' }], ['path', { d: 'M9 8h.01M12 6h.01M15 8h.01M7 5h.01M17 5h.01' }]],
  smart_scale: [['rect', { x: 4, y: 4, width: 16, height: 16, rx: 3 }], ['path', { d: 'M8 10a4.5 4.5 0 0 1 8 0M12 10l1.6 1.6' }]],
  garage_door: [['path', { d: 'M3 21V9l9-6 9 6v12' }], ['path', { d: 'M7 21v-9h10v9M7 15h10M7 18h10' }]],
  smart_blinds: [['rect', { x: 4, y: 3, width: 16, height: 18, rx: 1 }], ['path', { d: 'M4 8h16M4 12h16M4 16h16M20 16v4' }]],
  intercom: [['rect', { x: 6, y: 2, width: 12, height: 20, rx: 2 }], ['path', { d: 'M9 6h6M9 8.5h6M12 18.5h.01' }], ['circle', { cx: 12, cy: 13, r: 2 }]],
  motion_sensor: [['path', { d: 'M5 18a7 7 0 0 1 14 0z' }], ['path', { d: 'M3 9a12 12 0 0 1 3-3.5M21 9a12 12 0 0 0-3-3.5M12 14h.01' }]],
  door_sensor: [['rect', { x: 2, y: 8, width: 9, height: 8, rx: 1 }], ['rect', { x: 14, y: 8, width: 8, height: 8, rx: 1 }], ['path', { d: 'M12.5 10.5v3' }]],
  leak_sensor: [['path', { d: 'M12 3c4 5 6 7.5 6 10.5a6 6 0 0 1-12 0C6 10.5 8 8 12 3z' }], ['path', { d: 'M9 15a3 3 0 0 0 3 3' }]],
  weather_station: [['circle', { cx: 8, cy: 8, r: 2.6 }], ['path', { d: 'M8 2.5v1M2.5 8h1M4 4l.7.7M12 4l-.7.7' }], ['path', { d: 'M8 20a4 4 0 0 1 0-8 5 5 0 0 1 9.5 1.5A3 3 0 0 1 17 20z' }]],
  nvr: [['rect', { x: 2, y: 8, width: 20, height: 8, rx: 1.5 }], ['circle', { cx: 6, cy: 12, r: 1.3 }], ['path', { d: 'M10 10.5h9M10 13.5h9' }]],
  digital_signage: [['rect', { x: 6, y: 2, width: 12, height: 17, rx: 1 }], ['path', { d: 'M8 22h8M12 19v3' }]],
  label_printer: [['path', { d: 'M6 9V4h12v5' }], ['rect', { x: 3, y: 9, width: 18, height: 8, rx: 2 }], ['path', { d: 'M8 17v4h8v-4M6 12.5h.01' }]],
  time_clock: [['circle', { cx: 12, cy: 11, r: 8 }], ['path', { d: 'M12 7v4.5l3 2M9 21h6' }]],
  microcontroller: [['rect', { x: 6, y: 5, width: 12, height: 14, rx: 1 }], ['path', { d: 'M9 19v3h6v-3M3 8h3M3 11h3M3 14h3M18 8h3M18 11h3M18 14h3' }]],
  mini_pc: [['rect', { x: 4, y: 8, width: 16, height: 9, rx: 2.5 }], ['path', { d: 'M8 12.5h8M12 17v3M8 20h8' }]],
  bmc: [['rect', { x: 3, y: 4, width: 18, height: 16, rx: 1.5 }], ['path', { d: 'M7 9l3 2.5L7 14M12 15h5' }]],
  wireless_bridge: [['rect', { x: 8, y: 13, width: 8, height: 8, rx: 1.5 }], ['path', { d: 'M5 9a10 10 0 0 1 14 0M8 11.5a6 6 0 0 1 8 0M12 17h.01' }]],
  powerline: [['rect', { x: 6, y: 5, width: 12, height: 15, rx: 3 }], ['path', { d: 'M10 5V2.5M14 5V2.5M9 11h6M9 14.5h6' }]],
  vending_machine: [['rect', { x: 4, y: 2, width: 16, height: 20, rx: 2 }], ['rect', { x: 7, y: 5, width: 7, height: 10, rx: 1 }], ['path', { d: 'M17 6h.01M17 9h.01M7 19h10' }]],
  unknown: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M9.5 9.5a2.6 2.6 0 0 1 5 1c0 1.8-2.5 2-2.5 3.7M12 17h.01' }]],
};

/** Names offered in the icon picker (the server has the authoritative list). */
const ICON_NAMES = Object.keys(ICON_SHAPES);

// Menu icons: same drawing rules, but only for the sidebar (never offered as a device icon).
const NAV_SHAPES = {
  assets: [['rect', { x: 3, y: 4, width: 18, height: 12, rx: 1.5 }], ['path', { d: 'M9 20h6M12 16v4' }]],
  alerts: [['path', { d: 'M6 9a6 6 0 0 1 12 0c0 6 2.5 7 2.5 7h-17S6 15 6 9zM10 20a2 2 0 0 0 4 0' }]],
  findings: [['rect', { x: 5, y: 3, width: 14, height: 18, rx: 2 }], ['path', { d: 'M9 3v2h6V3M9 12l2 2 4-4' }]],
  topology: [['circle', { cx: 12, cy: 5, r: 2 }], ['circle', { cx: 5, cy: 19, r: 2 }], ['circle', { cx: 19, cy: 19, r: 2 }], ['path', { d: 'M12 7v4M12 11l-6 6M12 11l6 6' }]],
  ot: [['rect', { x: 3, y: 3, width: 18, height: 18, rx: 1.5 }], ['path', { d: 'M7 7h4M7 11h4M7 15h4M15 7h2M15 11h2M15 15h2' }]],
  trends: [['path', { d: 'M4 19V5M4 19h16M8 15l3-4 3 2 5-6' }]],
  events: [['path', { d: 'M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01' }]],
  compliance: [['path', { d: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z' }], ['path', { d: 'M9 12l2 2 4-4' }]],
  rules: [['path', { d: 'M4 7h9M17 7h3M4 17h3M11 17h9' }], ['circle', { cx: 15, cy: 7, r: 2 }], ['circle', { cx: 9, cy: 17, r: 2 }]],
  alerting: [['path', { d: 'M3 11v2a1 1 0 0 0 1 1h3l6 4V6L7 10H4a1 1 0 0 0-1 1zM17 9a4 4 0 0 1 0 6M19.5 6.5a8 8 0 0 1 0 11' }]],
  agents: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18' }]],
  users: [['circle', { cx: 12, cy: 8, r: 3.5 }], ['path', { d: 'M5 20a7 7 0 0 1 14 0' }]],
  settings: [['circle', { cx: 12, cy: 12, r: 3 }], ['path', { d: 'M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8' }]],
  audit: [['path', { d: 'M6 3h9l4 4v14H6zM14 3v5h5M9 13h7M9 17h7M9 9h2' }]],
};

/** Draw an icon as an <svg> element of `size` pixels. */
function icon(name, size = 20) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.7');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.classList.add('icon');
  for (const [tag, attrs] of ICON_SHAPES[name] || NAV_SHAPES[name] || ICON_SHAPES.unknown) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    svg.append(n);
  }
  return svg;
}

// Discovered device type -> icon, when nobody picked one by hand.
const TYPE_ICONS = {
  computer: 'desktop', laptop: 'laptop', server: 'server', 'virtual machine': 'virtual_machine', phone: 'phone',
  tablet: 'tablet', printer: 'printer', router: 'router', 'network device': 'switch', 'access point': 'access_point',
  nas: 'nas', camera: 'camera', 'media device': 'media_player', 'smart speaker': 'speaker', tv: 'tv', iot: 'iot',
  plc: 'plc', hmi: 'hmi', rtu: 'rtu', 'scada server': 'scada', 'engineering workstation': 'laptop', historian: 'server',
  'industrial switch': 'switch', 'industrial gateway': 'gateway', drive: 'drive', sensor: 'sensor', 'building controller': 'building',
  'thin client': 'thin_client', 'point of sale': 'pos', kiosk: 'kiosk', hypervisor: 'hypervisor', 'database server': 'database',
  'storage array': 'storage_array', kvm: 'kvm', pdu: 'pdu', ups: 'ups', 'load balancer': 'load_balancer', 'vpn gateway': 'vpn',
  firewall: 'firewall', 'security appliance': 'security_appliance', modem: 'modem', 'mesh node': 'mesh_node', 'cloud service': 'cloud',
  projector: 'projector', 'conference system': 'conference', 'voip phone': 'voip_phone', 'set-top box': 'media_player',
  'streaming stick': 'streaming_stick', 'game console': 'game_console', wearable: 'watch', 'smart plug': 'smart_plug',
  'smart light': 'smart_light', 'smart lock': 'smart_lock', doorbell: 'doorbell', 'badge reader': 'badge_reader',
  'alarm panel': 'alarm_panel', 'smoke detector': 'smoke_detector', thermostat: 'thermostat', 'hvac controller': 'hvac',
  'smart hub': 'smart_hub', 'robot vacuum': 'vacuum', appliance: 'appliance', '3d printer': 'printer_3d', scanner: 'scanner',
  'barcode scanner': 'barcode_scanner', 'medical device': 'medical', 'ev charger': 'ev_charger', 'solar inverter': 'inverter',
  vehicle: 'vehicle', 'wireless controller': 'access_point', 'safety controller': 'safety_controller',
  'protection relay': 'protection_relay', 'power meter': 'power_meter', 'remote io': 'remote_io', 'industrial pc': 'industrial_pc',
  'cnc machine': 'cnc', 'rfid reader': 'rfid', robot: 'robot', pump: 'pump', valve: 'valve', motor: 'motor',
  // robots, appliances, smart home, energy, office/IT extras
  'robot lawn mower': 'robot_mower', drone: 'drone', 'irrigation controller': 'irrigation', 'smart refrigerator': 'fridge',
  'washing machine': 'washing_machine', dishwasher: 'dishwasher', oven: 'oven', 'coffee machine': 'coffee_machine',
  'air purifier': 'air_purifier', 'air conditioner': 'air_conditioner', 'heat pump': 'heat_pump', 'water heater': 'water_heater',
  'smart meter': 'smart_meter', 'battery storage': 'battery_storage', soundbar: 'soundbar', 'av receiver': 'av_receiver',
  'smart display': 'smart_display', 'vr headset': 'vr_headset', 'e-reader': 'e_reader', 'baby monitor': 'baby_monitor',
  'pet feeder': 'pet_feeder', 'smart scale': 'smart_scale', 'garage door opener': 'garage_door', 'smart blinds': 'smart_blinds',
  intercom: 'intercom', 'motion sensor': 'motion_sensor', 'door sensor': 'door_sensor', 'leak sensor': 'leak_sensor',
  'weather station': 'weather_station', nvr: 'nvr', 'digital signage': 'digital_signage', 'label printer': 'label_printer',
  'time clock': 'time_clock', microcontroller: 'microcontroller', 'mini pc': 'mini_pc', 'management controller': 'bmc',
  'wireless bridge': 'wireless_bridge', 'powerline adapter': 'powerline', 'vending machine': 'vending_machine',
  'single-board computer': 'raspberry_pi',
};

/** The device type that goes with an icon (choosing an icon fills in the type). Operating-system icons imply none. */
const ICON_TYPES = (() => {
  const m = {};
  for (const [type, ic] of Object.entries(TYPE_ICONS)) if (!(ic in m)) m[ic] = type;
  return m;
})();

/** How the icon chooser groups its icons (an icon missing here lands in "Other"). */
const ICON_CATEGORIES = [
  ['Computers and phones', ['laptop', 'desktop', 'mini_pc', 'raspberry_pi', 'microcontroller', 'thin_client', 'virtual_machine', 'phone', 'tablet', 'e_reader', 'watch', 'server', 'hypervisor', 'database']],
  ['Network', ['router', 'switch', 'access_point', 'mesh_node', 'modem', 'wireless_bridge', 'powerline', 'firewall', 'security_appliance', 'load_balancer', 'vpn', 'cloud', 'gateway', 'bmc', 'kvm']],
  ['Storage and power', ['nas', 'storage_array', 'ups', 'pdu', 'battery_storage']],
  ['Office and retail', ['printer', 'printer_3d', 'label_printer', 'scanner', 'barcode_scanner', 'pos', 'kiosk', 'vending_machine', 'digital_signage', 'time_clock', 'projector', 'conference', 'voip_phone', 'badge_reader', 'rfid']],
  ['Video and audio', ['camera', 'nvr', 'tv', 'media_player', 'streaming_stick', 'game_console', 'vr_headset', 'speaker', 'soundbar', 'av_receiver', 'smart_display']],
  ['Smart home', ['smart_hub', 'smart_plug', 'smart_light', 'smart_lock', 'doorbell', 'intercom', 'thermostat', 'smart_blinds', 'garage_door', 'baby_monitor', 'pet_feeder', 'smart_scale', 'iot', 'sensor', 'motion_sensor', 'door_sensor', 'leak_sensor', 'smoke_detector', 'alarm_panel', 'weather_station', 'irrigation']],
  ['Appliances and robots', ['vacuum', 'robot_mower', 'drone', 'fridge', 'washing_machine', 'dishwasher', 'oven', 'coffee_machine', 'air_purifier', 'air_conditioner', 'heat_pump', 'water_heater', 'appliance']],
  ['Energy and vehicles', ['inverter', 'smart_meter', 'ev_charger', 'vehicle', 'power_meter']],
  ['Industrial', ['plc', 'hmi', 'rtu', 'scada', 'drive', 'robot', 'building', 'hvac', 'safety_controller', 'protection_relay', 'remote_io', 'industrial_pc', 'cnc', 'pump', 'valve', 'motor', 'medical']],
  ['Systems and brands', ['apple', 'windows', 'linux', 'android', 'unknown']],
];

/** The icon to show for an asset: the owner's choice, else a guess from what we know. */
function iconFor(a) {
  if (a.meta && a.meta.icon) return a.meta.icon;
  const name = ((a.display_name || (a.hostnames || [])[0] || '') + ' ' + (a.vendor || '')).toLowerCase();
  if (/plug|socket|switch1|shelly/.test(name) && a.device_type === 'iot') return 'smart_plug';
  if (/macbook|laptop/.test(name)) return 'laptop';
  if (TYPE_ICONS[a.device_type]) return TYPE_ICONS[a.device_type];
  const os = (a.os_guess || '').toLowerCase();
  if (/ios|ipados|macos|apple/.test(os)) return 'apple';
  if (os.includes('windows')) return 'windows';
  if (os.includes('android')) return 'android';
  if (os.includes('linux')) return 'linux';
  return 'unknown';
}
