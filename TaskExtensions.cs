namespace DNS_Bruteforce;

public static class TaskExtensions
{
    public static async Task<T> WithCancellation<T>(this Task<T> task, CancellationToken cancellationToken)
    {
        var delayTask = Task.Delay(-1, cancellationToken);
        var completedTask = await Task.WhenAny(task, delayTask);
        if (completedTask == delayTask)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        return await task;
    }
}
