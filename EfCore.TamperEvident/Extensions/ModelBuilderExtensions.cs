using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Extensions;

public static class ModelBuilderExtensions
{
    public static ModelBuilder AddTamperEvidentModels(this ModelBuilder builder)
    {
        builder.Entity<AuditLog>(entity =>
        {
            entity.ToTable("AuditLogs");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.TableName).HasMaxLength(256);
            entity.Property(x => x.RecordId).HasMaxLength(2048);
            entity.Property(x => x.PreviousHash).HasMaxLength(80);
            entity.Property(x => x.CurrentHash).HasMaxLength(80);
            entity.Property(x => x.UserId).HasMaxLength(256);
            entity.HasIndex(x => new { x.TableName, x.TimestampTicks }).IsUnique();
        });
        builder.Entity<AuditChainState>(entity =>
        {
            entity.ToTable("AuditChainStates");
            entity.HasKey(x => x.TableName);
            entity.Property(x => x.TableName).HasMaxLength(256);
            entity.Property(x => x.LastHash).HasMaxLength(80);
        });
        builder.Entity<PendingAnchor>(entity =>
        {
            entity.ToTable("PendingAnchors");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.TableName).HasMaxLength(256);
            entity.Property(x => x.AnchorHash).HasMaxLength(80);
            entity.Property(x => x.LastError).HasMaxLength(2048);
            entity.HasIndex(x => new { x.DeliveredAtUtc, x.CreatedAtUtc });
        });
        return builder;
    }
}
