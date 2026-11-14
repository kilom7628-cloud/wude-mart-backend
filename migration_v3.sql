ALTER TABLE payments ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'Telebirr';
ALTER TABLE payments ADD COLUMN customer_id INTEGER;
UPDATE payments SET customer_id = (SELECT customer_id FROM orders WHERE orders.id = payments.order_id) WHERE customer_id IS NULL;
