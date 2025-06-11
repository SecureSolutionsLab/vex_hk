
## Create OSV database

```sql
CREATE TABLE "osv" ("id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "osv_data" JSONB NOT NULL);
```