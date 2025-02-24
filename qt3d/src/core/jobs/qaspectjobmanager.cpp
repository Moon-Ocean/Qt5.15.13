/****************************************************************************
**
** Copyright (C) 2014 Klaralvdalens Datakonsult AB (KDAB).
** Contact: https://www.qt.io/licensing/
**
** This file is part of the Qt3D module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "qaspectjobmanager_p.h"

#include <QtCore/QAtomicInt>
#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QThread>
#include <QtCore/QFuture>
#include <Qt3DCore/private/qaspectmanager_p.h>
#include <Qt3DCore/private/qthreadpooler_p.h>
#include <Qt3DCore/private/task_p.h>

QT_BEGIN_NAMESPACE

namespace Qt3DCore {

QAspectJobManager::QAspectJobManager(QAspectManager *parent)
    : QAbstractAspectJobManager(parent)
    , m_threadPooler(new QThreadPooler(this))
    , m_aspectManager(parent)
{
}

QAspectJobManager::~QAspectJobManager()
{
}

void QAspectJobManager::initialize()
{
}

// Adds all Aspect Jobs to be processed for a frame
void QAspectJobManager::enqueueJobs(const QVector<QAspectJobPtr> &jobQueue)
{
    auto systemService = m_aspectManager ? m_aspectManager->serviceLocator()->systemInformation() : nullptr;
    if (systemService)
        systemService->writePreviousFrameTraces();

    // Convert QJobs to Tasks
    QHash<QAspectJob *, AspectTaskRunnable *> tasksMap;
    QVector<RunnableInterface *> taskList;
    taskList.reserve(jobQueue.size());
    for (const QAspectJobPtr &job : jobQueue) {
        AspectTaskRunnable *task = new AspectTaskRunnable(systemService);
        task->m_job = job;
        tasksMap.insert(job.data(), task);

        taskList << task;
    }

    for (const QAspectJobPtr &job : jobQueue) {
        const QVector<QWeakPointer<QAspectJob> > &deps = job->dependencies();
        AspectTaskRunnable *taskDepender = tasksMap.value(job.data());

        int dependerCount = 0;
        for (const QWeakPointer<QAspectJob> &dep : deps) {
            AspectTaskRunnable *taskDependee = tasksMap.value(dep.toStrongRef().data());
            // The dependencies here are not hard requirements, i.e., the dependencies
            // not in the jobQueue should already have their data ready.
            if (taskDependee) {
                taskDependee->m_dependers.append(taskDepender);
                ++dependerCount;
            }
        }

        taskDepender->m_dependerCount += dependerCount;
    }

    m_threadPooler->mapDependables(taskList);
}

// Wait for all aspects jobs to be completed
int QAspectJobManager::waitForAllJobs()
{
    return m_threadPooler->waitForAllJobs();
}

void QAspectJobManager::waitForPerThreadFunction(JobFunction func, void *arg)
{
    const int threadCount = QAspectJobManager::idealThreadCount();
    QAtomicInt atomicCount(threadCount);

    QVector<RunnableInterface *> taskList;
    for (int i = 0; i < threadCount; ++i) {
        SyncTaskRunnable *syncTask = new SyncTaskRunnable(func, arg, &atomicCount);
        taskList << syncTask;
    }

    QFuture<void> future = m_threadPooler->mapDependables(taskList);
    future.waitForFinished();
}

int QAspectJobManager::idealThreadCount()
{
    static int jobCount = 0;
    if (jobCount)
        return jobCount;

    const QByteArray maxThreadCount = qgetenv("QT3D_MAX_THREAD_COUNT");
    if (!maxThreadCount.isEmpty()) {
        bool conversionOK = false;
        const int maxThreadCountValue = maxThreadCount.toInt(&conversionOK);
        if (conversionOK) {
            jobCount = maxThreadCountValue;
            return jobCount;
        }
    }

    jobCount = QThread::idealThreadCount();
    return jobCount;
}

} // namespace Qt3DCore

QT_END_NAMESPACE

#include "moc_qaspectjobmanager_p.cpp"
