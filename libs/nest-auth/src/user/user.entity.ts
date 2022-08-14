/**
 * @author Pavith Madusara
 *
 * Created at 28-Feb-2021
 * Sunday at 11:40 AM
 */
import {
    BaseEntity,
    Column,
    CreateDateColumn,
    DeleteDateColumn,
    Entity,
    OneToMany,
    PrimaryColumn,
    UpdateDateColumn,
} from 'typeorm';
import {AuthProvider} from '@arkstatic/nest-auth/auth-provider.enum';
import {SessionEntity} from '@arkstatic/nest-auth/session/session.entity';

@Entity('user')
export class UserEntity extends BaseEntity {
    @PrimaryColumn()
    uuid: string;

    @Column({nullable: true})
    displayName?: string;

    @Column({nullable: true})
    displayPicture?: string;

    @Column()
    firstName: string;

    @Column()
    lastName: string;

    @Column({nullable: true, unique: true})
    phone?: string;

    @Column({nullable: true, unique: true})
    email?: string;

    @Column()
    identifier: string;

    @Column()
    verifier: string;

    @Column({type: 'varchar'})
    authProvider: AuthProvider;

    @Column({default: false})
    enable2FA: boolean;

    @Column({nullable: true})
    secret?: string;

    @Column({nullable: true})
    emailVerifiedAt?: Date;

    @Column({nullable: true})
    phoneVerifiedAt?: Date;

    @Column()
    createdBy: string;

    @Column()
    updatedBy: string;

    @Column()
    status: boolean;

    @CreateDateColumn()
    createdAt!: Date;

    @UpdateDateColumn()
    updatedAt!: Date;

    @DeleteDateColumn()
    deletedAt?: Date;

    /**
     * Relations =======================================================================================================
     */

    @OneToMany(
        () => SessionEntity,
        session => session.user,
        {cascade: true},
    )
    sessions: SessionEntity[];

}
