import { BaseEntity } from 'src/common/entity/base.entity';
import { Column, Entity, Index } from 'typeorm';

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

  constructor(partial: Partial<Auth>) {
    super(partial);
    Object.assign(this, partial);
  }
}
