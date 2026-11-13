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
    CONSTRAINT chk_document_dates_and_status CHECK (
    (expiry_date > issue_date OR expiry_date IS NULL)
    AND (NOT is_verified OR expiry_date IS NOT NULL)
    AND (expiry_date IS NULL OR (expiry_date - issue_date) <= 7305))
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


CREATE TABLE audit.function_calls (
    id SERIAL PRIMARY KEY,
    call_time TIMESTAMP WITH TIME ZONE DEFAULT now(),
    function_name VARCHAR(150) NOT NULL,
    caller_role VARCHAR(100) NOT NULL,
    input_params JSONB,
    success BOOLEAN NOT NULL,
    error_message TEXT
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
INSERT INTO app.identity_documents (profile_id, document_type_id, document_number, issue_date, expiry_date, is_verified)
SELECT 
    dp.id, 
    (SELECT id FROM ref.documents_types WHERE type_name = 'Паспорт гражданина РФ'), 
    '45' || cast(floor(random() * 90 + 10) as int) || ' ' || cast(floor(random() * 900000 + 100000) as int),
    d.issue_dt,
    d.issue_dt + interval '10 years',
    true
FROM app.digital_profiles dp
CROSS JOIN LATERAL (
    SELECT ('2015-01-01'::date + (random() * interval '5 years'))::date AS issue_dt
) d;

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





-- Создание функций

-- Функция предоставления доступа к серису
CREATE OR REPLACE FUNCTION app.grant_service_access(p_profile_id UUID, p_service_id INT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, ref, audit, public
AS $$
DECLARE
    v_caller VARCHAR := session_user;
    v_profile_trust INT;
    v_service_trust INT;
    v_is_active BOOLEAN;
BEGIN
    -- Валидация входных данных
    IF p_profile_id IS NULL OR p_service_id IS NULL THEN
        RAISE EXCEPTION 'Параметры p_profile_id и p_service_id не могут быть NULL';
    END IF;

    -- Проверка существования и статуса профиля
    SELECT trust_level_id, is_active INTO v_profile_trust, v_is_active 
    FROM app.digital_profiles WHERE id = p_profile_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Цифровой профиль не найден';
    END IF;
    IF NOT v_is_active THEN
        RAISE EXCEPTION 'Цифровой профиль деактивирован';
    END IF;

    -- Проверка существования сервиса
    SELECT required_trust_level INTO v_service_trust 
    FROM ref.digital_services WHERE id = p_service_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Сервис не найден';
    END IF;

    -- проверка уровня доверия
    IF v_profile_trust < v_service_trust THEN
        RAISE EXCEPTION 'Недостаточный уровень доверия для доступа к сервису';
    END IF;

    -- Выполнение операции
    INSERT INTO app.service_access_grants (profile_id, service_id, expires_at)
    VALUES (p_profile_id, p_service_id, now() + interval '1 year')
    ON CONFLICT (profile_id, service_id) 
    DO UPDATE SET expires_at = EXCLUDED.expires_at, granted_at = now();

    -- Логирование успешного выполнения
    INSERT INTO audit.function_calls(function_name, caller_role, input_params, success)
    VALUES ('app.grant_service_access', v_caller, jsonb_build_object('profile_id', p_profile_id, 'service_id', p_service_id), TRUE);

    RETURN TRUE;

EXCEPTION WHEN OTHERS THEN
    -- Перехват ошибки
    INSERT INTO audit.function_calls(function_name, caller_role, input_params, success, error_message)
    VALUES ('app.grant_service_access', v_caller, jsonb_build_object('profile_id', p_profile_id, 'service_id', p_service_id), FALSE, SQLERRM);
    RETURN FALSE;
END;
$$;



-- Функция регистрации биометрических данных
CREATE OR REPLACE FUNCTION app.register_biometrics(
    p_profile_id UUID, 
    p_bio_type_id INT, 
    p_template_hash TEXT, 
    p_raw_data_enc BYTEA
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, ref, audit, public
AS $$
DECLARE
    v_caller VARCHAR := session_user; 
    v_is_active BOOLEAN;
    v_retention_days INT;
BEGIN
    -- Валидация входных параметров
    IF p_profile_id IS NULL OR p_bio_type_id IS NULL THEN
        RAISE EXCEPTION 'ID профиля и типа биометрии не могут быть NULL';
    END IF;
    
    IF p_template_hash IS NULL OR length(trim(p_template_hash)) = 0 THEN
        RAISE EXCEPTION 'Хэш шаблона биометрии не может быть пустым';
    END IF;

    -- Проверка статуса профиля
    SELECT is_active INTO v_is_active 
    FROM app.digital_profiles WHERE id = p_profile_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Цифровой профиль не найден';
    END IF;
    IF NOT v_is_active THEN
        RAISE EXCEPTION 'Цифровой профиль деактивирован. Регистрация биометрии запрещена.';
    END IF;

    -- Проверка типа биометрии
    SELECT retention_period_days INTO v_retention_days
    FROM ref.biometric_types WHERE id = p_bio_type_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Недопустимый тип биометрии';
    END IF;

    -- Вставка или обновление данных
    INSERT INTO app.biometrics (profile_id, bio_type_id, template_hash, raw_data_enc, registrated_at)
    VALUES (p_profile_id, p_bio_type_id, p_template_hash, p_raw_data_enc, now())
    ON CONFLICT (id) DO UPDATE 
    SET template_hash = EXCLUDED.template_hash,
        raw_data_enc = EXCLUDED.raw_data_enc,
        registrated_at = EXCLUDED.registrated_at;

    -- Логирование успешного выполнения
    INSERT INTO audit.function_calls(function_name, caller_role, input_params, success)
    VALUES (
        'app.register_biometrics', 
        v_caller, 
        jsonb_build_object('profile_id', p_profile_id, 'bio_type_id', p_bio_type_id), 
        TRUE
    );

    RETURN TRUE;

EXCEPTION WHEN OTHERS THEN
    -- Перехват ошибки и логирование
    INSERT INTO audit.function_calls(function_name, caller_role, input_params, success, error_message)
    VALUES (
        'app.register_biometrics', 
        v_caller, 
        jsonb_build_object('profile_id', p_profile_id, 'bio_type_id', p_bio_type_id), 
        FALSE, 
        SQLERRM
    );
    RETURN FALSE;
END;
$$;



-- Функция верификация документа удостоверяющего личность
CREATE OR REPLACE FUNCTION app.verify_identity_document(
    p_document_number VARCHAR(50)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, ref, audit, public
AS $$
DECLARE
    v_caller VARCHAR := session_user;
    v_doc_id UUID;
    v_is_verified BOOLEAN;
    v_expiry_date DATE;
    v_requires_verification BOOLEAN;
BEGIN
    -- Валидация входа
    IF p_document_number IS NULL OR length(trim(p_document_number)) = 0 THEN
        RAISE EXCEPTION 'Номер документа не может быть пустым';
    END IF;

    -- Получение данных документа и его типа
    SELECT d.id, d.is_verified, d.expiry_date, dt.requires_verification 
    INTO v_doc_id, v_is_verified, v_expiry_date, v_requires_verification
    FROM app.identity_documents d
    JOIN ref.documents_types dt ON d.document_type_id = dt.id
    WHERE d.document_number = p_document_number;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Документ с номером % не найден', p_document_number;
    END IF;

    -- Проверка документов
    IF NOT v_requires_verification THEN
        RAISE EXCEPTION 'Этот тип документа не требует верификации';
    END IF;

    IF v_is_verified THEN
        RAISE EXCEPTION 'Документ уже верифицирован';
    END IF;

    IF v_expiry_date IS NOT NULL AND v_expiry_date < current_date THEN
        RAISE EXCEPTION 'Срок действия документа истек. Верификация невозможна.';
    END IF;

    -- Выполнение обновления
    UPDATE app.identity_documents 
    SET is_verified = true 
    WHERE id = v_doc_id;

    -- Логирование успеха
    INSERT INTO audit.function_calls(function_name, caller_role, input_params, success)
    VALUES (
        'app.verify_identity_document', 
        v_caller, 
        jsonb_build_object('document_number', p_document_number), 
        TRUE
    );

    RETURN TRUE;

EXCEPTION WHEN OTHERS THEN
    -- Логирование ошибки
    INSERT INTO audit.function_calls(function_name, caller_role, input_params, success, error_message)
    VALUES (
        'app.verify_identity_document', 
        v_caller, 
        jsonb_build_object('document_number', p_document_number), 
        FALSE, 
        SQLERRM
    );
    RETURN FALSE;
END;
$$;


REVOKE ALL ON FUNCTION app.grant_service_access(UUID, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.verify_identity_document(VARCHAR) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.register_biometrics(UUID, INT, TEXT, BYTEA) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.grant_service_access(UUID, INT) TO app_writer;
GRANT EXECUTE ON FUNCTION app.verify_identity_document(VARCHAR) TO app_writer;
GRANT EXECUTE ON FUNCTION app.register_biometrics(UUID, INT, TEXT, BYTEA) TO app_writer;





-- Справочник сегментов (контуров критичности и конфиденциальности данных)
CREATE TABLE IF NOT EXISTS ref.segments (
    id SERIAL PRIMARY KEY,
    segment_code VARCHAR(50) UNIQUE NOT NULL,
    segment_name VARCHAR(150) NOT NULL,
    confidentiality_level VARCHAR(50) NOT NULL,
    description TEXT
);

COMMENT ON TABLE ref.segments IS 'Справочник сегментов (контуров критичности и конфиденциальности данных граждан)';

-- Справочник привязки ролей БД к допустимым сегментам
CREATE TABLE IF NOT EXISTS ref.role_segments (
    role_name VARCHAR(100) NOT NULL,
    segment_id INT NOT NULL REFERENCES ref.segments(id) ON DELETE CASCADE,
    is_default BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (role_name, segment_id)
);

COMMENT ON TABLE ref.role_segments IS 'Сопоставление ролей СУБД и разрешенных сегментов данных';

-- Заполнение справочника сегментов
INSERT INTO ref.segments (id, segment_code, segment_name, confidentiality_level, description) VALUES
(1, 'SEG_PUBLIC',  'Общегражданский контур', 'PUBLIC',       'Базовый уровень критичности: стандартные цифровые профили граждан'),
(2, 'SEG_GOV',     'Ведомственный контур',   'CONFIDENTIAL', 'Повышенный уровень конфиденциальности: профили госслужащих и персонала КИИ'),
(3, 'SEG_SPECIAL', 'Специальный биометрический контур',    'SECRET',       'Высокий уровень критичности: спецсубъекты и защищенные биометрические шаблоны')
ON CONFLICT (id) DO NOTHING;

-- Заполнение привязки ролей к сегментам:
-- u_reader / app_reader: по умолчанию сегмент 1
-- u_writer / app_writer: по умолчанию сегмент 1, разрешено переключение на сегмент 2 (сегмент 3 запрещен)
-- u_dml_admin / dml_admin: по умолчанию сегмент 2, разрешено переключение на сегмент 3
-- u_auditor / auditor и u_owner / app_owner: доступ ко всем сегментам (1, 2, 3)
INSERT INTO ref.role_segments (role_name, segment_id, is_default) VALUES
('u_reader',    1, true),
('app_reader',  1, true),
('u_writer',    1, true),
('u_writer',    2, false),
('app_writer',  1, true),
('app_writer',  2, false),
('u_dml_admin', 2, true),
('u_dml_admin', 3, false),
('dml_admin',   2, true),
('dml_admin',   3, false),
('u_auditor',   1, true),
('u_auditor',   2, false),
('u_auditor',   3, false),
('auditor',     1, true),
('auditor',     2, false),
('auditor',     3, false),
('u_owner',     1, true),
('u_owner',     2, false),
('u_owner',     3, false),
('app_owner',   1, true),
('app_owner',   2, false),
('app_owner',   3, false)
ON CONFLICT (role_name, segment_id) DO NOTHING;


-- Предоставление прав на новые справочники и чтение таблиц схемы app для роли auditor
GRANT SELECT ON ref.segments, ref.role_segments TO app_reader, app_writer, dml_admin, auditor;
GRANT USAGE ON SCHEMA app, ref TO auditor;
GRANT SELECT ON ALL TABLES IN SCHEMA app, ref TO auditor;


-- ФУНКЦИИ ПЕРЕДАЧИ КОНТЕКСТА И РЕЗЕРВНОГО ОПРЕДЕЛЕНИЯ СЕГМЕНТА

-- Вспомогательная функция резервного сопоставления
CREATE OR REPLACE FUNCTION app.get_role_default_segment()
RETURNS INT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ref, app, public
AS $$
    SELECT rs.segment_id
    FROM ref.role_segments rs
    WHERE rs.role_name IN (current_user, session_user)
      AND rs.is_default = true
    ORDER BY CASE WHEN rs.role_name = current_user THEN 1 ELSE 2 END
    LIMIT 1;
$$;

-- Функция вычисления активного сегмента сессии
CREATE OR REPLACE FUNCTION app.get_active_segment_id()
RETURNS INT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ref, app, public
AS $$
    SELECT COALESCE(
        NULLIF(current_setting('app.segment_id', true), '')::INT,
        app.get_role_default_segment()
    );
$$;

-- Функция установки контекста сессии
CREATE OR REPLACE FUNCTION app.set_session_ctx(p_segment_id INT, p_actor_id TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, ref, audit, public
AS $$
DECLARE
    v_caller VARCHAR := current_user;
    v_session_usr VARCHAR := session_user;
    v_has_access BOOLEAN := false;
BEGIN
    -- Проверка обязательных параметров
    IF p_segment_id IS NULL OR p_actor_id IS NULL OR length(trim(p_actor_id)) = 0 THEN
        RAISE EXCEPTION 'Параметры segment_id и actor_id не могут быть пустыми';
    END IF;

    -- Проверка существования сегмента в справочнике ref.segments
    IF NOT EXISTS (SELECT 1 FROM ref.segments WHERE id = p_segment_id) THEN
        RAISE EXCEPTION 'Сегмент с идентификатором % не существует', p_segment_id;
    END IF;

    -- Проверка права вызывающей роли (current_user или session_user) на запрошенный сегмент
    SELECT EXISTS (
        SELECT 1
        FROM ref.role_segments rs
        WHERE rs.role_name IN (v_caller, v_session_usr)
          AND rs.segment_id = p_segment_id
    ) INTO v_has_access;

    IF NOT v_has_access THEN
        -- Логирование неуспешной попытки смены контекста
        INSERT INTO audit.function_calls(function_name, caller_role, input_params, success, error_message)
        VALUES (
            'app.set_session_ctx',
            v_caller,
            jsonb_build_object('segment_id', p_segment_id, 'actor_id', p_actor_id, 'session_user', v_session_usr),
            FALSE,
            format('Доступ запрещен: роль %s (сессия %s) не имеет прав на сегмент %s', v_caller, v_session_usr, p_segment_id)
        );

        RAISE EXCEPTION 'Доступ запрещен: роль % не имеет прав на сегмент %', v_caller, p_segment_id;
    END IF;

    -- Установка локальных параметров GUC (SET LOCAL эквивалент через set_config(..., true))
    PERFORM set_config('app.segment_id', p_segment_id::TEXT, true);
    PERFORM set_config('app.actor_id', trim(p_actor_id), true);
    PERFORM set_config('app.user_id', trim(p_actor_id), true);

    -- Логирование успешной установки контекста
    INSERT INTO audit.function_calls(function_name, caller_role, input_params, success)
    VALUES (
        'app.set_session_ctx',
        v_caller,
        jsonb_build_object('segment_id', p_segment_id, 'actor_id', p_actor_id, 'session_user', v_session_usr),
        TRUE
    );

    RETURN TRUE;
END;
$$;

REVOKE ALL ON FUNCTION app.get_role_default_segment() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.get_active_segment_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.set_session_ctx(INT, TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.get_role_default_segment() TO app_reader, app_writer, dml_admin, auditor, app_owner;
GRANT EXECUTE ON FUNCTION app.get_active_segment_id() TO app_reader, app_writer, dml_admin, auditor, app_owner;
GRANT EXECUTE ON FUNCTION app.set_session_ctx(INT, TEXT) TO app_reader, app_writer, dml_admin, auditor, app_owner;


-- Добавление segment_id во все ключевые таблицы
ALTER TABLE app.citizens
    ADD COLUMN IF NOT EXISTS segment_id INT REFERENCES ref.segments(id) ON DELETE RESTRICT
    DEFAULT COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment(), 1);

ALTER TABLE app.digital_profiles
    ADD COLUMN IF NOT EXISTS segment_id INT REFERENCES ref.segments(id) ON DELETE RESTRICT
    DEFAULT COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment(), 1);

ALTER TABLE app.identity_documents
    ADD COLUMN IF NOT EXISTS segment_id INT REFERENCES ref.segments(id) ON DELETE RESTRICT
    DEFAULT COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment(), 1);

ALTER TABLE app.biometrics
    ADD COLUMN IF NOT EXISTS segment_id INT REFERENCES ref.segments(id) ON DELETE RESTRICT
    DEFAULT COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment(), 1);

ALTER TABLE app.service_access_grants
    ADD COLUMN IF NOT EXISTS segment_id INT REFERENCES ref.segments(id) ON DELETE RESTRICT
    DEFAULT COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment(), 1);

-- Распределение существующих тестовых записей по 3 сегментам
WITH numbered_citizens AS (
    SELECT id, row_number() OVER (ORDER BY snils) AS rn
    FROM app.citizens
)
UPDATE app.citizens c
SET segment_id = CASE
    WHEN nc.rn <= 4 THEN 1  -- 4 гражданина в SEG_PUBLIC (сегмент 1)
    WHEN nc.rn <= 7 THEN 2  -- 3 гражданина в SEG_GOV (сегмент 2)
    ELSE 3                  -- 3 гражданина в SEG_SPECIAL (сегмент 3)
END
FROM numbered_citizens nc
WHERE c.id = nc.id;

-- Синхронизация segment_id в дочерних таблицах по профилю гражданина
UPDATE app.digital_profiles dp
SET segment_id = c.segment_id
FROM app.citizens c
WHERE dp.citizen_id = c.id;

-- Гарантированное заполнение документов с соблюдением CHECK-ограничения expiry_date, если таблица пуста
INSERT INTO app.identity_documents (profile_id, document_type_id, document_number, issue_date, expiry_date, is_verified, segment_id)
SELECT
    dp.id,
    (SELECT id FROM ref.documents_types WHERE type_name = 'Паспорт гражданина РФ'),
    '45' || lpad((row_number() OVER (ORDER BY dp.id))::text, 2, '0') || ' ' || (100000 + row_number() OVER (ORDER BY dp.id))::text,
    '2018-05-10'::date,
    '2028-05-10'::date,
    true,
    dp.segment_id
FROM app.digital_profiles dp
WHERE NOT EXISTS (SELECT 1 FROM app.identity_documents d WHERE d.profile_id = dp.id);

UPDATE app.identity_documents d
SET segment_id = dp.segment_id
FROM app.digital_profiles dp
WHERE d.profile_id = dp.id;

UPDATE app.biometrics b
SET segment_id = dp.segment_id
FROM app.digital_profiles dp
WHERE b.profile_id = dp.id;

UPDATE app.service_access_grants sag
SET segment_id = dp.segment_id
FROM app.digital_profiles dp
WHERE sag.profile_id = dp.id;

-- Установка ограничения NOT NULL после заполнения данных
ALTER TABLE app.citizens ALTER COLUMN segment_id SET NOT NULL;
ALTER TABLE app.digital_profiles ALTER COLUMN segment_id SET NOT NULL;
ALTER TABLE app.identity_documents ALTER COLUMN segment_id SET NOT NULL;
ALTER TABLE app.biometrics ALTER COLUMN segment_id SET NOT NULL;
ALTER TABLE app.service_access_grants ALTER COLUMN segment_id SET NOT NULL;

-- Создание покрывающих индексов
CREATE INDEX IF NOT EXISTS idx_citizens_segment_snils
    ON app.citizens (segment_id, snils);

CREATE INDEX IF NOT EXISTS idx_profiles_segment_active_citizen
    ON app.digital_profiles (segment_id, is_active, citizen_id);

CREATE INDEX IF NOT EXISTS idx_documents_segment_profile_num
    ON app.identity_documents (segment_id, profile_id, document_number);

CREATE INDEX IF NOT EXISTS idx_biometrics_segment_profile_type
    ON app.biometrics (segment_id, profile_id, bio_type_id);

CREATE INDEX IF NOT EXISTS idx_grants_segment_profile_service
    ON app.service_access_grants (segment_id, profile_id, service_id);

CREATE INDEX IF NOT EXISTS idx_role_segments_lookup
    ON ref.role_segments (role_name, is_default, segment_id);


-- Включение RLS и FORCE RLS на всех ключевых таблицах
ALTER TABLE app.citizens ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.citizens FORCE ROW LEVEL SECURITY;

ALTER TABLE app.digital_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.digital_profiles FORCE ROW LEVEL SECURITY;

ALTER TABLE app.identity_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.identity_documents FORCE ROW LEVEL SECURITY;

ALTER TABLE app.biometrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.biometrics FORCE ROW LEVEL SECURITY;

ALTER TABLE app.service_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.service_access_grants FORCE ROW LEVEL SECURITY;


-- Создание политик RLS (SELECT / INSERT / UPDATE / DELETE + РЕЖИМ AUDITOR)


-- Таблица app.citizens
CREATE POLICY citizens_owner_all_policy ON app.citizens
    FOR ALL TO app_owner
    USING (true) WITH CHECK (true);

CREATE POLICY citizens_select_rls_policy ON app.citizens
    FOR SELECT TO app_reader, app_writer, dml_admin, auditor
    USING (
        current_user = 'auditor'
        OR pg_has_role(current_user, 'auditor', 'MEMBER')
        OR segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY citizens_insert_rls_policy ON app.citizens
    FOR INSERT TO app_writer, dml_admin
    WITH CHECK (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY citizens_update_rls_policy ON app.citizens
    FOR UPDATE TO app_writer, dml_admin
    USING (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    )
    WITH CHECK (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY citizens_delete_rls_policy ON app.citizens
    FOR DELETE TO app_writer, dml_admin
    USING (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );


-- Таблица app.digital_profiles
CREATE POLICY profiles_select_rls_policy ON app.digital_profiles
    FOR SELECT TO app_reader, app_writer, dml_admin, auditor
    USING (
        current_user = 'auditor'
        OR pg_has_role(current_user, 'auditor', 'MEMBER')
        OR (
            is_active = true
            AND segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
        )
    );

CREATE POLICY profiles_insert_rls_policy ON app.digital_profiles
    FOR INSERT TO app_writer, dml_admin
    WITH CHECK (
        is_active = true
        AND segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY profiles_update_rls_policy ON app.digital_profiles
    FOR UPDATE TO app_writer, dml_admin
    USING (
        is_active = true
        AND segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    )
    WITH CHECK (
        is_active = true
        AND segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY profiles_delete_rls_policy ON app.digital_profiles
    FOR DELETE TO app_writer, dml_admin
    USING (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );


-- Таблица app.identity_documents
CREATE POLICY documents_owner_all_policy ON app.identity_documents
    FOR ALL TO app_owner
    USING (true) WITH CHECK (true);

CREATE POLICY documents_select_rls_policy ON app.identity_documents
    FOR SELECT TO app_reader, app_writer, dml_admin, auditor
    USING (
        current_user = 'auditor'
        OR pg_has_role(current_user, 'auditor', 'MEMBER')
        OR segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY documents_insert_rls_policy ON app.identity_documents
    FOR INSERT TO app_writer, dml_admin
    WITH CHECK (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY documents_update_rls_policy ON app.identity_documents
    FOR UPDATE TO app_writer, dml_admin
    USING (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    )
    WITH CHECK (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY documents_delete_rls_policy ON app.identity_documents
    FOR DELETE TO app_writer, dml_admin
    USING (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );


-- Таблица app.biometrics
CREATE POLICY biometrics_owner_all_policy ON app.biometrics
    FOR ALL TO app_owner
    USING (true) WITH CHECK (true);

CREATE POLICY biometrics_select_rls_policy ON app.biometrics
    FOR SELECT TO app_reader, app_writer, dml_admin, auditor
    USING (
        current_user = 'auditor'
        OR pg_has_role(current_user, 'auditor', 'MEMBER')
        OR segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY biometrics_insert_rls_policy ON app.biometrics
    FOR INSERT TO app_writer, dml_admin
    WITH CHECK (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY biometrics_update_rls_policy ON app.biometrics
    FOR UPDATE TO app_writer, dml_admin
    USING (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    )
    WITH CHECK (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY biometrics_delete_rls_policy ON app.biometrics
    FOR DELETE TO app_writer, dml_admin
    USING (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );


-- Таблица app.service_access_grants
CREATE POLICY grants_owner_all_policy ON app.service_access_grants
    FOR ALL TO app_owner
    USING (true) WITH CHECK (true);

CREATE POLICY grants_select_rls_policy ON app.service_access_grants
    FOR SELECT TO app_reader, app_writer, dml_admin, auditor
    USING (
        current_user = 'auditor'
        OR pg_has_role(current_user, 'auditor', 'MEMBER')
        OR segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY grants_insert_rls_policy ON app.service_access_grants
    FOR INSERT TO app_writer, dml_admin
    WITH CHECK (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );

CREATE POLICY grants_update_rls_policy ON app.service_access_grants
    FOR UPDATE TO app_writer, dml_admin
    USING (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    )
    WITH CHECK (
        segment_id = COALESCE(NULLIF(current_setting('app.segment_id', true), '')::INT, app.get_role_default_segment())
    );