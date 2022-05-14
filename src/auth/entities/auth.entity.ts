import { BaseEntity } from 'src/common/entity/base.entity';
import { Column, Entity, Index, OneToMany } from 'typeorm';
import { Token } from './token.entity';

@Entity()
export class Auth extends BaseEntity {
  @Index({ unique: true })
  @Column({ nullable: false })
  email: string;

  @Column({ nullable: false })
  password: string;

  @Column({ name: 'is_email_verified', default: false })
  isEmailVerified: boolean;

  @Column({ name: 'user_id', nullable: true })
  userId: number;

  @OneToMany(() => Token, token => token.auth)
  tokens: Token[];

  constructor(partial: Partial<Auth>) {
    super(partial);
    Object.assign(this, partial);
  }
}
