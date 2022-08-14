/**
 * @author Pavith Madusara
 *
 * Created at 28-Feb-2021
 * Sunday at 1:09 PM
 */
import {
    BaseEntity,
    Column,
    CreateDateColumn,
    Entity,
    ManyToOne,
    PrimaryGeneratedColumn,
    UpdateDateColumn,
} from 'typeorm';
import {UserEntity} from '@arkstatic/nest-auth/user/user.entity';

@Entity('session')
export class SessionEntity extends BaseEntity {

    /**
     * Auto Generated Primary key & Session ID
     */
    @PrimaryGeneratedColumn('uuid')
    sessionId: string;

    /**
     * User's IP Address from Request
     */
    @Column()
    ipAddress: string;

    /**
     * User-Agent String from Request Headers
     */
    @Column()
    userAgent: string;

    /**
     * Key to sign Refresh Tokens
     */
    @Column()
    key: string;

    @CreateDateColumn()
    createdAt!: Date;

    @UpdateDateColumn()
    updatedAt!: Date;

    /**
     * Relations =======================================================================================================
     */
    @ManyToOne(() => UserEntity, user => user.sessions, {onDelete: 'CASCADE'})
    user: UserEntity;
}
