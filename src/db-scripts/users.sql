-- Intentional SQL injection example for security testing

CREATE PROCEDURE GetUser @id VARCHAR(100)
AS
BEGIN
    DECLARE @query NVARCHAR(MAX);
    SET @query = 'SELECT * FROM users WHERE id = ' + @id;
    EXEC(@query);
END;
