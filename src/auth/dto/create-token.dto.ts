import { ServiceType } from 'src/common/enum/auth.enum';
import { Auth } from '../entities/auth.entity';

export class CreateTokenDto {
  serviceType: ServiceType;
  accessToken: string;
  expiresDate: Date;
  refreshToken?: string;
  serviceUserId?: string;
  idToken?: string;
  auth: Auth;

  constructor(partial: Partial<CreateTokenDto>) {
    Object.assign(this, partial);
  }
}
