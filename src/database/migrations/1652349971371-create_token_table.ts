import { MigrationInterface, QueryRunner } from 'typeorm';

export class createTokenTable1652349971371 implements MigrationInterface {
  name = 'createTokenTable1652349971371';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE \`token\` (\`id\` int NOT NULL AUTO_INCREMENT, \`created_date\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), \`updated_date\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), \`deleted_date\` datetime(6) NULL, \`service_type\` enum ('app', 'google', 'facebook') NOT NULL, \`service_user_id\` varchar(255) NULL, \`id_token\` varchar(255) NULL, \`access_token\` varchar(255) NULL, \`refresh_token\` varchar(255) NULL, \`expires_date\` datetime NOT NULL, UNIQUE INDEX \`IDX_b95cd28e9bf58b05f50e4ff909\` (\`refresh_token\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX \`IDX_b95cd28e9bf58b05f50e4ff909\` ON \`token\``);
    await queryRunner.query(`DROP TABLE \`token\``);
  }
}
