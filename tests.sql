-- КЕЙС 1 [Позитивный]: Чтение разрешённых таблиц ролью чтения (app_reader)
SET ROLE u_reader;
SELECT id, first_name, snils 
FROM app.citizens 
LIMIT 2;
-- Ожидание: Успешная выборка данных.


-- КЕЙС 2 [Негативный]: Попытка выполнения DDL неадмином (app_writer)
SET ROLE u_writer;
CREATE TABLE app.secret_data (id INT);
-- Ожидание: Ошибка "permission denied for schema app". Создавать таблицы может только ddl_admin или владелец.


-- КЕЙС 3 [Позитивный]: Выполнение разрешенного DML ролью (app_writer)
SET ROLE u_writer;
UPDATE app.citizens 
SET first_name = 'Иван (обновлен)' 
WHERE snils = '111-222-333 44';
-- Ожидание: Успешное выполнение (UPDATE 1).


-- КЕЙС 4 [Негативный]: Прямая попытка DML в схему audit (app_writer)
SET ROLE u_writer;
DELETE FROM audit.login_log;
-- Ожидание: Ошибка "permission denied for table login_log". Никто кроме владельца/функций не может писать в аудит.


-- КЕЙС 5 [Негативный]: Вызов SECURITY DEFINER функции без прав (app_reader)
SET ROLE u_reader;
SELECT app.verify_identity_document('1234567890');
-- Ожидание: Ошибка "permission denied for function verify_identity_document". Права на выполнение (EXECUTE) выданы только app_writer.


-- КЕЙС 6 [Негативный]: SECURITY DEFINER с невалидными данными (app_writer)
SET ROLE u_writer;
-- Пытаемся верифицировать несуществующий номер документа
SELECT app.verify_identity_document('FAKE-DOC-999');
-- Ожидание: Функция отработает и вернет FALSE, перехватив нашу кастомную ошибку "Документ с номером FAKE-DOC-999 не найден".


-- КЕЙС 7 [Позитивный]: SECURITY DEFINER с валидными данными (app_writer)
SET ROLE u_writer;
INSERT INTO app.identity_documents (profile_id, document_type_id, document_number, issue_date)
VALUES (
    (SELECT id FROM app.digital_profiles LIMIT 1),
    (SELECT id FROM ref.documents_types WHERE type_name = 'Паспорт гражданина РФ' LIMIT 1),
    'TEST-DOC-777',
    '2022-01-01'
);

-- Вызов функции для успешной верификации созданного документа
SELECT app.verify_identity_document('TEST-DOC-777');
-- Ожидание: Функция вернет TRUE. Операция выполнена от лица владельца.



-- Для корректной работы тестов на уровень доверия, принудительно зададим 
-- известным профилям минимальный и максимальный уровни доверия 
UPDATE app.digital_profiles 
SET trust_level_id = (SELECT id FROM ref.trust_levels WHERE level_code = 'BASIC')
WHERE citizen_id = (SELECT id FROM app.citizens WHERE snils = '111-222-333 44');

UPDATE app.digital_profiles 
SET trust_level_id = (SELECT id FROM ref.trust_levels WHERE level_code = 'BIOMETRIC')
WHERE citizen_id = (SELECT id FROM app.citizens WHERE snils = '111-222-333 45');


-- КЕЙС 9 [Негативный]: grant_service_access – недостаточный уровень доверия
SET ROLE u_writer;
SELECT app.grant_service_access(
    (SELECT id FROM app.digital_profiles WHERE trust_level_id = (SELECT id FROM ref.trust_levels WHERE level_code = 'BASIC') LIMIT 1),
    (SELECT id FROM ref.digital_services WHERE required_trust_level = (SELECT id FROM ref.trust_levels WHERE level_code = 'BIOMETRIC') LIMIT 1)
);
-- Ожидание: FALSE (Функция перехватит ошибку "Недостаточный уровень доверия для доступа к сервису").


-- КЕЙС 10 [Позитивный]: grant_service_access – успешная выдача доступа
SET ROLE u_writer;
SELECT app.grant_service_access(
    (SELECT id FROM app.digital_profiles WHERE trust_level_id = (SELECT id FROM ref.trust_levels WHERE level_code = 'BIOMETRIC') LIMIT 1),
    (SELECT id FROM ref.digital_services WHERE required_trust_level = (SELECT id FROM ref.trust_levels WHERE level_code = 'BASIC') LIMIT 1)
);
-- Ожидание: TRUE (Доступ предоставлен, так как BIOMETRIC > BASIC).


-- КЕЙС 11 [Негативный]: register_biometrics – пустой хэш или неверный тип
SET ROLE u_writer;
SELECT app.register_biometrics(
    (SELECT id FROM app.digital_profiles LIMIT 1),
    (SELECT id FROM ref.biometric_types LIMIT 1),
    '', -- Нарушение бизнес-логики: пустой хэш
    '\xDEADBEEF'::bytea
);
-- Ожидание: FALSE (Ошибка "Хэш шаблона биометрии не может быть пустым").


-- КЕЙС 12 [Позитивный]: register_biometrics – успешная регистрация
SET ROLE u_writer;

SELECT app.register_biometrics(
    (SELECT id FROM app.digital_profiles LIMIT 1),
    3,
    'a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890',
    '\xDEADBEEF01020304'::bytea
);

-- Ожидание: TRUE (Слепок успешно добавлен или обновлен через UPSERT).


-- КЕЙС 13 [Позитивный]: Проверка журнала вызовов для новых функций (аудитор)
SET ROLE u_auditor;
SELECT 
    call_time, 
    function_name, 
    success, 
    error_message 
FROM audit.function_calls 
WHERE function_name IN ('app.grant_service_access', 'app.register_biometrics')
ORDER BY call_time DESC 
LIMIT 4;
-- Ожидание: 4 новые записи. Две с success = false (и текстами бизнес-ошибок), две с success = true.

RESET ROLE;







-- Таблица с ограничением CHECK
CREATE TABLE app.test_docs_check (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_number VARCHAR(50) NOT NULL,
    issue_date DATE NOT NULL,
    expiry_date DATE,
    is_verified BOOLEAN DEFAULT false,
    CONSTRAINT chk_document_dates_and_status CHECK (
        (expiry_date > issue_date OR expiry_date IS NULL)
        AND (NOT is_verified OR expiry_date IS NOT NULL)
        AND (expiry_date IS NULL OR (expiry_date - issue_date) <= 7305)
    )
);


-- Таблица без CHECK-ограничения
CREATE TABLE app.test_docs_trigger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_number VARCHAR(50) NOT NULL,
    issue_date DATE NOT NULL,
    expiry_date DATE,
    is_verified BOOLEAN DEFAULT false
);

-- Триггерная функция валидации
CREATE OR REPLACE FUNCTION app.fn_validate_document_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Проверка согласованности дат
    IF NEW.expiry_date IS NOT NULL AND NEW.expiry_date <= NEW.issue_date THEN
        RAISE EXCEPTION 'Ошибка валидации: expiry_date (%) должна быть позже issue_date (%)', 
            NEW.expiry_date, NEW.issue_date
            USING ERRCODE = 'check_violation';
    END IF;

    -- Проверка наличия срока действия для верифицированных документов
    IF NEW.is_verified AND NEW.expiry_date IS NULL THEN
        RAISE EXCEPTION 'Ошибка валидации: верифицированный документ обязан иметь дату окончания действия'
            USING ERRCODE = 'not_null_violation';
    END IF;

    -- Проверка срока действия
    IF NEW.expiry_date IS NOT NULL AND (NEW.expiry_date - NEW.issue_date) > 7305 THEN
        RAISE EXCEPTION 'Ошибка валидации: срок действия документа не может превышать 20 лет (7305 дней)'
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$;

-- Назначение BEFORE-триггера
CREATE TRIGGER trg_validate_document_rules
BEFORE INSERT OR UPDATE ON app.test_docs_trigger
FOR EACH ROW
EXECUTE FUNCTION app.fn_validate_document_trigger();



-- Замер 1: Массовая вставка 10 000 строк с CHECK-ограничением
DO $$
DECLARE
    v_start TIMESTAMPTZ;
    v_duration NUMERIC;
BEGIN
    TRUNCATE TABLE app.test_docs_check;
    v_start := clock_timestamp();

    INSERT INTO app.test_docs_check (document_number, issue_date, expiry_date, is_verified)
    SELECT
        'DOC-CHK-' || i,
        '2022-01-01'::date + (i % 365),
        '2022-01-01'::date + (i % 365) + 3650,
        (i % 2 = 0)
    FROM generate_series(1, 10000) AS i;

    v_duration := 1000 * EXTRACT(EPOCH FROM (clock_timestamp() - v_start));
    RAISE NOTICE 'Время выполнения вставки 10 000 строк (CHECK): % мс', round(v_duration, 2);
END;
$$;

-- Замер 2: Массовая вставка 10 000 строк с валидацией через ТРИГГЕР
DO $$
DECLARE
    v_start TIMESTAMPTZ;
    v_duration NUMERIC;
BEGIN
    TRUNCATE TABLE app.test_docs_trigger;
    v_start := clock_timestamp();

    INSERT INTO app.test_docs_trigger (document_number, issue_date, expiry_date, is_verified)
    SELECT
        'DOC-TRG-' || i,
        '2022-01-01'::date + (i % 365),
        '2022-01-01'::date + (i % 365) + 3650,
        (i % 2 = 0)
    FROM generate_series(1, 10000) AS i;

    v_duration := 1000 * EXTRACT(EPOCH FROM (clock_timestamp() - v_start));
    RAISE NOTICE 'Время выполнения вставки 10 000 строк (TRIGGER): % мс', round(v_duration, 2);
END;
$$;





-- ЛР3


-- ТЕСТ 1: Резервный путь (fallback) сопоставления роли -> segment_id (без вызова set_session_ctx)
-- Роль u_reader по умолчанию привязана к сегменту 1 (SEG_PUBLIC)
RESET ROLE;
BEGIN;
SET LOCAL ROLE u_reader;
SELECT current_user AS active_role, app.get_active_segment_id() AS resolved_segment;
SELECT id, first_name, last_name, snils, segment_id FROM app.citizens;
COMMIT;

-- ТЕСТ 2: Попытка чтения «чужих» строк из сегментов 2 и 3 (должно быть пусто — 0 строк)
BEGIN;
SET LOCAL ROLE u_reader;
SELECT id, first_name, last_name, snils, segment_id
FROM app.citizens
WHERE segment_id IN (2, 3);
COMMIT;

-- ТЕСТ 3: Успешная установка контекста через app.set_session_ctx(2, 'operator_gov_01')
-- Роль u_writer имеет право на сегменты 1 и 2
BEGIN;
SET LOCAL ROLE u_writer;
SELECT app.set_session_ctx(2, 'operator_gov_01') AS ctx_set_result;
SELECT current_setting('app.segment_id', true) AS guc_segment_id,
       current_setting('app.actor_id', true) AS guc_actor_id;
SELECT id, first_name, last_name, snils, segment_id FROM app.citizens;
COMMIT;

-- ТЕСТ 4: Ошибка вызова app.set_session_ctx() при передаче недоступного роли сегмента (сегмент 3)
-- Роль u_writer НЕ имеет доступа к сегменту 3 (SEG_SPECIAL) — ожидается ERROR
BEGIN;
SET LOCAL ROLE u_writer;
SELECT app.set_session_ctx(3, 'unauthorized_actor');
ROLLBACK;

-- ТЕСТ 5: Корректная вставка (INSERT) новой записи в своем сегменте (сегмент 1)
BEGIN;
SET LOCAL ROLE u_writer;
SELECT app.set_session_ctx(1, 'operator_mfc_01');
INSERT INTO app.citizens (first_name, last_name, birth_date, snils, segment_id)
VALUES ('Павел', 'Орлов', '1993-06-12', '222-333-444 55', 1)
RETURNING id, first_name, last_name, snils, segment_id;
COMMIT;

-- ТЕСТ 6: Ошибка вставки (INSERT) записи с чужим segment_id (попытка вставить segment_id = 2 из сегмента 1)
-- Ожидается ошибка: new row violates row-level security policy for table "citizens"
BEGIN;
SET LOCAL ROLE u_writer;
SELECT app.set_session_ctx(1, 'operator_mfc_01');
INSERT INTO app.citizens (first_name, last_name, birth_date, snils, segment_id)
VALUES ('Нарушитель', 'Тестовый', '1991-01-01', '999-888-777 66', 2);
ROLLBACK;

-- ТЕСТ 7: Корректное обновление (UPDATE) строки в своем сегменте (сегмент 1)
BEGIN;
SET LOCAL ROLE u_writer;
SELECT app.set_session_ctx(1, 'operator_mfc_01');
UPDATE app.citizens
SET last_name = 'Орлов-Соколов'
WHERE snils = '222-333-444 55'
RETURNING id, first_name, last_name, snils, segment_id;
COMMIT;

-- ТЕСТ 8: Запрет кросс-сегментного обновления (UPDATE): попытка перенести строку из сегмента 1 в сегмент 2
-- Ожидается ошибка WITH CHECK: new row violates row-level security policy for table "citizens"
BEGIN;
SET LOCAL ROLE u_writer;
SELECT app.set_session_ctx(1, 'operator_mfc_01');
UPDATE app.citizens
SET segment_id = 2
WHERE snils = '222-333-444 55';
ROLLBACK;

-- ТЕСТ 9: Попытка удаления (DELETE) чужих строк (возвращает DELETE 0) и штатное удаление своей строки (DELETE 1)
BEGIN;
SET LOCAL ROLE u_writer;
SELECT app.set_session_ctx(1, 'operator_mfc_01');
-- Попытка удалить записи сегмента 2 (затронуто 0 строк)
DELETE FROM app.citizens WHERE segment_id = 2;
-- Удаление тестовой записи своего сегмента 1 (затронута 1 строка)
DELETE FROM app.citizens WHERE snils = '222-333-444 55'
RETURNING id, first_name, last_name, snils, segment_id;
COMMIT;

-- ТЕСТ 10: Режим суперпользователя (ревизора) для роли auditor — видимость всех сегментов без ограничений RLS
BEGIN;
SET LOCAL ROLE auditor;
SELECT current_user AS active_role;
SELECT s.id AS segment_id, s.segment_code, s.confidentiality_level, count(c.id) AS citizens_count
FROM ref.segments s
LEFT JOIN app.citizens c ON c.segment_id = s.id
GROUP BY s.id, s.segment_code, s.confidentiality_level
ORDER BY s.id;
SELECT id, first_name, last_name, snils, segment_id FROM app.citizens ORDER BY segment_id, snils;
COMMIT;
RESET ROLE;