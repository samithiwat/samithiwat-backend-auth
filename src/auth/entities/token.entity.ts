import { BaseEntity } from 'src/common/entity/base.entity';
import { ServiceType } from 'src/common/enum/auth.enum';
import { Column, Entity, Index, ManyToOne } from 'typeorm';
import { Auth } from './auth.entity';

@Entity()
export class Token extends BaseEntity {
  @Column({ type: 'enum', enum: ServiceType, name: 'service_type' })
  serviceType: ServiceType;

  @Column({ name: 'service_user_id', nullable: true })
  serviceUserId: string;

  @Column({ name: 'id_token', nullable: true })
  idToken: string;

  @Index()
  @Column({ name: 'access_token', nullable: true })
  accessToken: string;

  @Index({ unique: true })
  @Column({ name: 'refresh_token', nullable: true })
  refreshToken: string;

  @Column({ name: 'expires_date' })
  expiresDate: Date;

  @ManyToOne(() => Auth, auth => auth.tokens)
  auth: Auth;

  constructor(partial: Partial<Token>) {
    super(partial);
    Object.assign(this, partial);
  }
}
