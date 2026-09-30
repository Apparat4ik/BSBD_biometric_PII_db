-- Создание групповых ролей
CREATE ROLE app_reader NOLOGIN; -- Чтение данных приложения
CREATE ROLE app_writer NOLOGIN; -- Чтение/запись данных приложения
CREATE ROLE app_owner NOLOGIN; -- Владелец приложения (может изменять структуру)
CREATE ROLE auditor NOLOGIN; -- Роль для аудита

CREATE ROLE ddl_admin NOLOGIN; -- Может делать только DDL (создание/изменение таблиц, схем)
CREATE ROLE dml_admin NOLOGIN; -- Может делать только DML (INSERT/UPDATE/DELETE)
CREATE ROLE security_admin NOLOGIN; -- Администрирование безопасности: GRANT/REVOKE

-- Создание логин-ролей с атрибутом NOINHERIT
CREATE ROLE u_reader LOGIN NOINHERIT PASSWORD 'Qqwerty_123';
CREATE ROLE u_writer LOGIN NOINHERIT PASSWORD 'Qqwerty_123';
CREATE ROLE u_owner LOGIN NOINHERIT PASSWORD 'Qqwerty_123';
CREATE ROLE u_auditor LOGIN NOINHERIT PASSWORD 'Qqwerty_123';
CREATE ROLE u_ddl_admin LOGIN NOINHERIT PASSWORD 'Qqwerty_123';
CREATE ROLE u_dml_admin LOGIN NOINHERIT PASSWORD 'Qqwerty_123';
CREATE ROLE u_sec_admin LOGIN NOINHERIT PASSWORD 'Qqwerty_123';

-- Привязка пользователей к группам
GRANT app_reader TO u_reader;
GRANT app_writer TO u_writer;
GRANT app_owner TO u_owner;
GRANT auditor TO u_auditor;
GRANT ddl_admin TO u_ddl_admin;
GRANT dml_admin TO u_dml_admin;
GRANT security_admin TO u_sec_admin;

-- Права для администратора безопасности
ALTER ROLE security_admin CREATEROLE;
GRANT app_owner TO security_admin; 


CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Создание схем 
CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION app_owner;
CREATE SCHEMA IF NOT EXISTS ref AUTHORIZATION app_owner;
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION app_owner;
CREATE SCHEMA IF NOT EXISTS stg AUTHORIZATION app_owner;


-- Схема ref
CREATE TABLE ref.trust_levels (
    id SERIAL PRIMARY KEY,
    level_code VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255)
);

CREATE TABLE ref.biometric_types (
    id SERIAL PRIMARY KEY,
    type_name VARCHAR(100) UNIQUE NOT NULL,
    algorithm_version VARCHAR(50),
    retention_period_days INT CHECK (retention_period_days > 0)
);

CREATE TABLE ref.documents_types (
    id SERIAL PRIMARY KEY,
    type_name VARCHAR(100) UNIQUE NOT NULL,
    requires_verification BOOLEAN DEFAULT false
);

CREATE TABLE ref.digital_services (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(150) UNIQUE NOT NULL,
    required_trust_level INT REFERENCES ref.trust_levels(id) ON DELETE RESTRICT
);


-- Схема app
CREATE TABLE app.citizens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    birth_date DATE NOT NULL,
    snils VARCHAR(14) UNIQUE NOT NULL
);

CREATE TABLE app.digital_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    citizen_id UUID NOT NULL REFERENCES app.citizens(id) ON DELETE CASCADE UNIQUE,
    login VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    trust_level_id INT REFERENCES ref.trust_levels(id) ON DELETE RESTRICT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE app.identity_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES app.digital_profiles(id) ON DELETE CASCADE,
    document_type_id INT REFERENCES ref.documents_types(id) ON DELETE RESTRICT,
    document_number VARCHAR(50) UNIQUE NOT NULL,
    issue_date DATE NOT NULL,
    expiry_date DATE,
    is_verified BOOLEAN DEFAULT false,
    CHECK (expiry_date > issue_date OR expiry_date IS NULL) 
);

CREATE TABLE app.biometrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES app.digital_profiles(id) ON DELETE CASCADE,
    bio_type_id INT REFERENCES ref.biometric_types(id) ON DELETE RESTRICT,
    template_hash TEXT NOT NULL,
    raw_data_enc BYTEA,
    registrated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE app.service_access_grants (
    profile_id UUID REFERENCES app.digital_profiles(id) ON DELETE CASCADE,
    service_id INT REFERENCES ref.digital_services(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (profile_id, service_id),
    CHECK (expires_at > granted_at OR expires_at IS NULL)
);


-- Схема audit
CREATE TABLE audit.login_log (
    id SERIAL PRIMARY KEY,
    login_time TIMESTAMP WITH TIME ZONE DEFAULT now(),
    db_username VARCHAR(100) NOT NULL,
    client_ip INET
);


-- Схема stg
CREATE TABLE stg.import_buffer (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_payload JSONB NOT NULL,
    import_date TIMESTAMP WITH TIME ZONE DEFAULT now(),
    source_system VARCHAR(100)
);

-- Коментарии к таблицам
COMMENT ON TABLE ref.biometric_types IS 'Справочник типов биометрических данных';
COMMENT ON TABLE ref.documents_types IS 'Справочник типов идентификационных документов';
COMMENT ON TABLE ref.trust_levels IS 'Справочник уровней доверия';
COMMENT ON TABLE ref.digital_services IS 'Справочник государственных сервисов, имеющих доступ к биометрическим данным';
COMMENT ON TABLE app.citizens IS 'Таблица данных граждан';
COMMENT ON TABLE app.digital_profiles IS 'Таблица цифровых профилей авторизации';
COMMENT ON TABLE app.identity_documents IS 'Таблица документов, удостоверяющих личность';
COMMENT ON TABLE app.biometrics IS 'Таблица биометрических данных граждан';
COMMENT ON TABLE app.service_access_grants IS 'Таблица, связывающая цифровые профили с государственными сервисами';
COMMENT ON TABLE audit.login_log IS 'Журнал авторизации';
COMMENT ON TABLE stg.import_buffer IS 'Буфер загрузки данных';




-- Генерация тестовых данных

-- 1. Заполняем справочники
INSERT INTO ref.trust_levels (level_code, description) VALUES
('BASIC', 'Базовый уровень (только телефон или почта)'),
('STANDARD', 'Стандартный уровень (подтвержден СНИЛС и Паспорт)'),
('VERIFIED', 'Подтвержденный уровень (очное подтверждение)'),
('BIOMETRIC', 'Биометрический уровень (высший уровень доверия)');

INSERT INTO ref.biometric_types (type_name, algorithm_version, retention_period_days) VALUES
('Лицо (2D)', 'FaceNet_v2', 1825),
('Лицо (3D)', 'FaceID_v3', 1825),
('Отпечаток пальца', 'FingerMatch_v1', 1825),
('Голос', 'VoiceRec_v1.5', 1825);

INSERT INTO ref.documents_types (type_name, requires_verification) VALUES
('Паспорт гражданина РФ', true),
('СНИЛС', true),
('Заграничный паспорт', true),
('Водительское удостоверение', false);

INSERT INTO ref.digital_services (service_name, required_trust_level) VALUES
('Запись на прием к врачу', (SELECT id FROM ref.trust_levels WHERE level_code = 'BASIC')),
('Проверка штрафов ГИБДД', (SELECT id FROM ref.trust_levels WHERE level_code = 'STANDARD')),
('Регистрация ИП', (SELECT id FROM ref.trust_levels WHERE level_code = 'VERIFIED')),
('Оформление ипотеки онлайн', (SELECT id FROM ref.trust_levels WHERE level_code = 'BIOMETRIC'));

-- 2. Заполняем граждан (10 строк)
INSERT INTO app.citizens (first_name, last_name, birth_date, snils) VALUES
('Иван', 'Иванов', '1990-05-15', '111-222-333 44'),
('Мария', 'Смирнова', '1985-08-20', '111-222-333 45'),
('Алексей', 'Петров', '1992-11-10', '111-222-333 46'),
('Елена', 'Соколова', '1988-03-25', '111-222-333 47'),
('Дмитрий', 'Волков', '1975-12-05', '111-222-333 48'),
('Ольга', 'Морозова', '1995-07-30', '111-222-333 49'),
('Сергей', 'Новиков', '1980-01-18', '111-222-333 50'),
('Анна', 'Зайцева', '2000-09-12', '111-222-333 51'),
('Виктор', 'Кузнецов', '1968-04-22', '111-222-333 52'),
('Екатерина', 'Попова', '1998-02-14', '111-222-333 53');

-- 3. Заполняем профили граждан (пароли хешируются через pgcrypto)
INSERT INTO app.digital_profiles (citizen_id, login, password_hash, trust_level_id)
SELECT 
    id, 
    'user_' || split_part(snils, '-', 3) || '@gos.ru', 
    crypt('SecurePass123!', gen_salt('bf', 8)), 
    (SELECT id FROM ref.trust_levels ORDER BY random() LIMIT 1)
FROM app.citizens;

-- 4. Добавляем паспорта (связь с цифровым профилем)
INSERT INTO app.identity_documents (profile_id, document_type_id, document_number, issue_date, is_verified)
SELECT 
    dp.id, 
    (SELECT id FROM ref.documents_types WHERE type_name = 'Паспорт гражданина РФ'), 
    '45' || cast(floor(random() * 90 + 10) as int) || ' ' || cast(floor(random() * 900000 + 100000) as int),
    '2015-01-01'::date + (random() * (interval '5 years')),
    true
FROM app.digital_profiles dp;

-- 5. Добавляем тестовые биометрические слепки для части профилей (шифрование raw_data_enc)
INSERT INTO app.biometrics (profile_id, bio_type_id, template_hash, raw_data_enc)
SELECT 
    dp.id,
    (SELECT id FROM ref.biometric_types WHERE type_name = 'Лицо (2D)'),
    encode(digest('dummy_face_data_' || dp.login, 'sha256'), 'hex'),
    pgp_sym_encrypt('sensitive_binary_data', 'secret_key_from_env')
FROM app.digital_profiles dp
LIMIT 5;

-- 6. Добавляем доступы к сервисам
INSERT INTO app.service_access_grants (profile_id, service_id, expires_at)
SELECT 
    dp.id,
    ds.id,
    now() + interval '1 year'
FROM app.digital_profiles dp
CROSS JOIN ref.digital_services ds
WHERE random() > 0.7;



-- Назначение привелегий и защита данных

-- Отзыв прав у PUBLIC
REVOKE ALL ON DATABASE citizen_id_secure FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA app, ref, audit, stg FROM PUBLIC;

-- Базовый доступ на подключение
GRANT CONNECT ON DATABASE citizen_id_secure TO u_reader, u_writer, u_owner, u_auditor, u_ddl_admin, u_dml_admin, u_sec_admin;

-- Права для app_owner
GRANT ALL PRIVILEGES ON SCHEMA app, ref, audit, stg TO app_owner;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA app, ref, audit, stg TO app_owner;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA app, ref, audit, stg TO app_owner;

-- Разделение обязанностей

-- DDL Admin может создавать и менять структуру бд, но не данные
GRANT USAGE ON SCHEMA app, ref, stg, audit TO ddl_admin;
GRANT CREATE ON SCHEMA app, ref, stg, audit TO ddl_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA app, ref, stg, audit TO ddl_admin;
REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA app, ref, stg, audit FROM ddl_admin;

-- DML Admin может изменять данные внутри таблиц, но не меняет структуру
GRANT USAGE ON SCHEMA app, ref, stg, audit TO dml_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app, ref, stg TO dml_admin;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA app, ref, stg TO dml_admin;

-- Security Admin запрет на любой доступ к бизнес-данным, он только управляет ролями
REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app, ref, stg, audit FROM security_admin;

-- Права для ролей приложения
GRANT USAGE ON SCHEMA app, ref TO app_reader, app_writer;

-- Чтение
GRANT SELECT ON ALL TABLES IN SCHEMA app, ref TO app_reader;
GRANT SELECT, USAGE ON ALL SEQUENCES IN SCHEMA app, ref TO app_reader;

-- Чтение и запись
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app, ref TO app_writer;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA app, ref TO app_writer;

-- Изоляция схемы audit
GRANT USAGE ON SCHEMA audit TO auditor;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO auditor;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO auditor;

-- Запрет прямой вставки в аудит для всех, кроме владельца/триггера
REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA audit FROM PUBLIC, app_reader, app_writer, dml_admin;

-- Настройка привилегий по умолчанию

-- Для будущих таблиц, созданных владельцем
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app, ref 
    GRANT SELECT ON TABLES TO app_reader;

ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app, ref 
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_writer;

ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA audit 
    GRANT SELECT ON TABLES TO auditor;

-- Для будущих последовательностей
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app, ref 
    GRANT USAGE, SELECT ON SEQUENCES TO app_reader;

ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app, ref 
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO app_writer;


-- Включаем RLS для таблицы профилей
ALTER TABLE app.digital_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.digital_profiles FORCE ROW LEVEL SECURITY;

-- Политика для владельца: видит и может изменять всё
CREATE POLICY profiles_owner_policy 
ON app.digital_profiles 
FOR ALL 
TO app_owner 
USING (true) 
WITH CHECK (true);

-- Политика для читателей и писателей: видят только активные профили
CREATE POLICY profiles_active_only_policy 
ON app.digital_profiles 
FOR SELECT 
TO app_reader, app_writer 
USING (is_active = true);

-- Политика для писателей: могут обновлять только активные профили
CREATE POLICY profiles_update_active_policy 
ON app.digital_profiles 
FOR UPDATE 
TO app_writer 
USING (is_active = true)
WITH CHECK (is_active = true);


-- Функция записи лога при подключении
CREATE OR REPLACE FUNCTION audit.log_connection()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = 'app, public' 
AS $$
BEGIN
    INSERT INTO audit.login_log(db_username, client_ip)
    VALUES (session_user, inet_client_addr());
END;
$$;

-- Событийный триггер, который срабатывает при инициализации сессии
CREATE EVENT TRIGGER login_trigger ON login
    EXECUTE FUNCTION audit.log_connection();

-- Выдаем право security_admin на администрирование этой функции
GRANT EXECUTE ON FUNCTION audit.log_connection() TO security_admin;