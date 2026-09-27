create table users
(
    id         bigserial
        primary key,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name       text,
    username   text,
    password   text
);

create index idx_users_deleted_at
    on users (deleted_at);

