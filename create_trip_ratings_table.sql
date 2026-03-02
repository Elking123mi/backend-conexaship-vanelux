-- Run this in the Supabase SQL Editor to create the ratings table

CREATE TABLE IF NOT EXISTS trip_ratings (
    id            BIGSERIAL PRIMARY KEY,
    booking_id    BIGINT       NOT NULL UNIQUE REFERENCES vlx_bookings(id) ON DELETE CASCADE,
    driver_id     TEXT,
    user_id       TEXT,
    rating        SMALLINT     NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment       TEXT         DEFAULT '',
    created_at    TIMESTAMPTZ  DEFAULT NOW()
);

-- Index for driver stats queries
CREATE INDEX IF NOT EXISTS idx_trip_ratings_driver_id ON trip_ratings (driver_id);

-- Optional: enable Row Level Security so users can only read their own ratings
-- ALTER TABLE trip_ratings ENABLE ROW LEVEL SECURITY;
