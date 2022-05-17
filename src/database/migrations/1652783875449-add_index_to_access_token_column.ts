import {MigrationInterface, QueryRunner} from "typeorm";

export class addIndexToAccessTokenColumn1652783875449 implements MigrationInterface {
    name = 'addIndexToAccessTokenColumn1652783875449'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE INDEX \`IDX_d5b9f4694521b7fbb121aff385\` ON \`token\` (\`access_token\`)`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX \`IDX_d5b9f4694521b7fbb121aff385\` ON \`token\``);
    }

}
