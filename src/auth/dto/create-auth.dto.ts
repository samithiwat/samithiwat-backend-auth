export class CreateAuthDto {
  email: string;
  password: string;

  constructor(partial: Partial<CreateAuthDto>) {
    Object.assign(this, partial);
  }
}
