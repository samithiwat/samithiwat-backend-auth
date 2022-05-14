export class CredentialDto {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;

  constructor(partial: Partial<CredentialDto>) {
    Object.assign(this, partial);
  }
}
