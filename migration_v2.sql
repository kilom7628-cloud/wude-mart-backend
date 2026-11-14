CREATE TABLE IF NOT EXISTS payment_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    account_name TEXT NOT NULL,
    instructions TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS order_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    sender_role TEXT NOT NULL CHECK(sender_role IN ('admin', 'customer', 'system')),
    message_type TEXT NOT NULL DEFAULT 'general'
        CHECK(message_type IN ('general', 'payment_received', 'payment_approved', 'payment_rejected', 'info_requested', 'status_update')),
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);
