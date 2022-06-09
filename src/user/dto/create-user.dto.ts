export class CreateUserDto {
  firstname: string;
  lastname: string;
  displayName: string;
  imageUrl?: string;

  constructor(partial: Partial<CreateUserDto>) {
    Object.assign(this, partial);
  }
}
