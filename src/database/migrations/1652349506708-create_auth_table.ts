import { MigrationInterface, QueryRunner } from 'typeorm';

export class createAuthTable1652349506708 implements MigrationInterface {
  name = 'createAuthTable1652349506708';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE \`auth\` (\`id\` int NOT NULL AUTO_INCREMENT, \`created_date\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), \`updated_date\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), \`deleted_date\` datetime(6) NULL, \`email\` varchar(255) NOT NULL, \`password\` varchar(255) NOT NULL, \`is_email_verified\` tinyint NOT NULL DEFAULT 0, \`user_id\` int NULL, UNIQUE INDEX \`IDX_b54f616411ef3824f6a5c06ea4\` (\`email\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX \`IDX_b54f616411ef3824f6a5c06ea4\` ON \`auth\``);
    await queryRunner.query(`DROP TABLE \`auth\``);
  }
}
