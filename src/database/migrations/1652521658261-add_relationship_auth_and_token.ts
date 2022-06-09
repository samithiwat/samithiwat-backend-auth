import { MigrationInterface, QueryRunner } from 'typeorm';

export class addRelationshipAuthAndToken1652521658261 implements MigrationInterface {
  name = 'addRelationshipAuthAndToken1652521658261';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE \`token\` ADD \`authId\` int NULL`);
    await queryRunner.query(
      `ALTER TABLE \`token\` ADD CONSTRAINT \`FK_b807b83ea727332c8b2fad6f0ec\` FOREIGN KEY (\`authId\`) REFERENCES \`auth\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE \`token\` DROP FOREIGN KEY \`FK_b807b83ea727332c8b2fad6f0ec\``,
    );
    await queryRunner.query(`ALTER TABLE \`token\` DROP COLUMN \`authId\``);
  }
}
