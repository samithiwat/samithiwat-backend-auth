export class LoginDto {
  email: string;
  password: string;

  constructor(partial: Partial<LoginDto>) {
    Object.assign(this, partial);
  }
}
