import { MigrationInterface, QueryRunner } from 'typeorm';

export class addIndexToUserIdColumn1652526739212 implements MigrationInterface {
  name = 'addIndexToUserIdColumn1652526739212';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE \`auth\` ADD UNIQUE INDEX \`IDX_9922406dc7d70e20423aeffadf\` (\`user_id\`)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE \`auth\` DROP INDEX \`IDX_9922406dc7d70e20423aeffadf\``);
  }
}
